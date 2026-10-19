package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrVerificationScope = errors.New("无指令复核权限或指令不存在")
var ErrVerificationInput = errors.New("复核参数无效")

type VerificationInput struct {
	Outcome  string      `json:"outcome"`
	Expected string      `json:"expected"`
	Observed string      `json:"observed"`
	EventIDs []uuid.UUID `json:"eventIds"`
}

type VerificationEvidence struct {
	ID       uuid.UUID       `json:"id"`
	Ts       time.Time       `json:"ts"`
	Source   string          `json:"source"`
	ClassUID int             `json:"classUid"`
	Raw      json.RawMessage `json:"raw,omitempty"`
}

type Verification struct {
	ID            uuid.UUID              `json:"id"`
	CommandID     uuid.UUID              `json:"commandId"`
	GroupID       *uuid.UUID             `json:"groupId"`
	CreatedAt     time.Time              `json:"createdAt"`
	Reviewer      string                 `json:"reviewer"`
	CommandStatus string                 `json:"commandStatus"`
	Outcome       string                 `json:"outcome"`
	Expected      string                 `json:"expected"`
	Observed      string                 `json:"observed"`
	Evidence      []VerificationEvidence `json:"evidence"`
}

func EnsureVerificationSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS command_verifications (
 id uuid PRIMARY KEY, command_id uuid NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
 group_id uuid, created_at timestamptz NOT NULL, reviewer text NOT NULL,
 command_status text NOT NULL, outcome text NOT NULL CHECK (outcome IN ('effective','ineffective','inconclusive')),
 expected text NOT NULL, observed text NOT NULL, evidence jsonb NOT NULL);
 CREATE INDEX IF NOT EXISTS command_verifications_command ON command_verifications(command_id,created_at);`)
	return err
}

func (in VerificationInput) validate() error {
	if in.Outcome != "effective" && in.Outcome != "ineffective" && in.Outcome != "inconclusive" {
		return fmt.Errorf("%w：outcome 必须为 effective / ineffective / inconclusive", ErrVerificationInput)
	}
	for _, text := range []string{in.Expected, in.Observed} {
		if strings.TrimSpace(text) == "" || len(text) > 4000 || strings.ContainsRune(text, 0) {
			return fmt.Errorf("%w：预期和观察说明必填且各不超过 4000 字节", ErrVerificationInput)
		}
	}
	if len(in.EventIDs) > 20 || (in.Outcome != "inconclusive" && len(in.EventIDs) == 0) {
		return fmt.Errorf("%w：明确结论需要 1–20 条后续事件证据", ErrVerificationInput)
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range in.EventIDs {
		if id == uuid.Nil || seen[id] {
			return fmt.Errorf("%w：事件 ID 无效或重复", ErrVerificationInput)
		}
		seen[id] = true
	}
	return nil
}

// RecordVerification 记录人工复核意见，不改变执行回执，也不把事件存在解释成机器验证成功。
// 归属/成员资格在事务内锁定，审计失败则整体回滚。证据快照随复核留存。
func RecordVerification(ctx context.Context, db *sql.DB, userID, commandID uuid.UUID, in VerificationInput) (*Verification, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var reviewer, role string
	if err := tx.QueryRowContext(ctx, `SELECT username,role FROM users WHERE id=$1 FOR SHARE`, userID).Scan(&reviewer, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationScope
		}
		return nil, err
	}
	var assetID uuid.UUID
	var group uuid.NullUUID
	var status string
	var issued time.Time
	if err := tx.QueryRowContext(ctx, `SELECT c.asset_id,a.group_id,c.status,c.created_at FROM commands c JOIN assets a ON a.id=c.asset_id WHERE c.id=$1 FOR SHARE OF c,a`, commandID).Scan(&assetID, &group, &status, &issued); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationScope
		}
		return nil, err
	}
	if role != "admin" {
		var membership string
		if !group.Valid {
			return nil, ErrVerificationScope
		}
		if err := tx.QueryRowContext(ctx, `SELECT role FROM group_members WHERE user_id=$1 AND group_id=$2 AND role IN ('analyst','admin') FOR SHARE`, userID, group.UUID).Scan(&membership); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrVerificationScope
			}
			return nil, err
		}
	}
	out := &Verification{ID: uuid.New(), CommandID: commandID, CreatedAt: time.Now().UTC(), Reviewer: reviewer, CommandStatus: status, Outcome: in.Outcome, Expected: in.Expected, Observed: in.Observed, Evidence: make([]VerificationEvidence, 0, len(in.EventIDs))}
	if group.Valid {
		out.GroupID = &group.UUID
	}
	for _, id := range in.EventIDs {
		var e VerificationEvidence
		if err := tx.QueryRowContext(ctx, `SELECT id,ts,source,class_uid,raw FROM events WHERE id=$1 AND asset_id=$2 AND ts >= $3 AND ts <= $4 FOR SHARE`, id, assetID, issued, out.CreatedAt).Scan(&e.ID, &e.Ts, &e.Source, &e.ClassUID, &e.Raw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w：证据必须是同资产下发后的已发生事件", ErrVerificationInput)
			}
			return nil, err
		}
		out.Evidence = append(out.Evidence, e)
	}
	evidence, err := json.Marshal(out.Evidence)
	if err != nil {
		return nil, err
	}
	if len(evidence) > 1024*1024 {
		return nil, fmt.Errorf("%w：证据快照超过 1 MiB", ErrVerificationInput)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO command_verifications(id,command_id,group_id,created_at,reviewer,command_status,outcome,expected,observed,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, out.ID, commandID, out.GroupID, out.CreatedAt, reviewer, status, in.Outcome, in.Expected, in.Observed, evidence)
	if err != nil {
		return nil, err
	}
	detail, _ := json.Marshal(map[string]any{"verificationId": out.ID, "outcome": out.Outcome, "eventIds": in.EventIDs, "commandStatus": status})
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(id,ts,username,action,target,detail,remote_addr) VALUES($1,$2,$3,'command_verification_recorded',$4,$5,'verification-service')`, uuid.New(), out.CreatedAt, reviewer, commandID.String(), string(detail))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

const verificationScope = ` FROM command_verifications v JOIN commands c ON c.id=v.command_id JOIN assets a ON a.id=c.asset_id JOIN users u ON u.id=$1
 WHERE v.command_id=$2 AND (u.role='admin' OR (
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=v.group_id AND m.role IN ('viewer','analyst','admin')) AND
 EXISTS(SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=a.group_id AND m.role IN ('viewer','analyst','admin'))))`

// ListVerifications 同时约束复核时归组与当前资产归组，多取一条供 API 判断截断。
func ListVerifications(ctx context.Context, db *sql.DB, userID, commandID uuid.UUID) ([]Verification, error) {
	rows, err := db.QueryContext(ctx, `SELECT v.id,v.command_id,v.group_id,v.created_at,v.reviewer,v.command_status,v.outcome,v.expected,v.observed,
 COALESCE((SELECT jsonb_agg(e - 'raw') FROM jsonb_array_elements(v.evidence) e),'[]'::jsonb)
`+verificationScope+`
 ORDER BY v.created_at DESC,v.id DESC LIMIT 101`, userID, commandID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Verification, 0)
	for rows.Next() {
		var v Verification
		var evidence []byte
		if err := rows.Scan(&v.ID, &v.CommandID, &v.GroupID, &v.CreatedAt, &v.Reviewer, &v.CommandStatus, &v.Outcome, &v.Expected, &v.Observed, &evidence); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(evidence, &v.Evidence); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVerification 只读取一条授权复核及其留存原文，不能跨指令引用其他复核 ID。
func GetVerification(ctx context.Context, db *sql.DB, userID, commandID, verificationID uuid.UUID) (*Verification, error) {
	var v Verification
	var evidence []byte
	err := db.QueryRowContext(ctx, `SELECT v.id,v.command_id,v.group_id,v.created_at,v.reviewer,v.command_status,v.outcome,v.expected,v.observed,v.evidence`+verificationScope+` AND v.id=$3`, userID, commandID, verificationID).Scan(&v.ID, &v.CommandID, &v.GroupID, &v.CreatedAt, &v.Reviewer, &v.CommandStatus, &v.Outcome, &v.Expected, &v.Observed, &evidence)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(evidence, &v.Evidence); err != nil {
		return nil, err
	}
	return &v, nil
}
