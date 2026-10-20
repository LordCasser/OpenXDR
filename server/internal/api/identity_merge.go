package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/identity"
)

// 人工确认/拒绝合并候选与撤销：写入与审计同一事务提交，并与后台重算共用组锁。
// 确认只把一个「主机内归属」的账号改挂到同组身份上，原链接撤销留痕；撤销人工链接后账号回到按强证据计算的默认归属。

var errIdentityHidden = errors.New("身份不存在或不可访问")

// identityAccess 在事务内核对身份可见性与写权限：组 viewer 可读，analyst/admin 可改。
func identityAccess(ctx context.Context, tx *sql.Tx, id, user uuid.UUID) (uuid.UUID, bool, error) {
	var group uuid.UUID
	var writable bool
	err := tx.QueryRowContext(ctx, `SELECT i.group_id,`+fmt.Sprintf(canWriteGroup, 2, "i.group_id")+`
 FROM identities i JOIN identity_accounts anchor ON anchor.id=i.anchor_account_id
 WHERE i.id=$1 AND `+fmt.Sprintf(canReadGroup, 2, "i.group_id")+` AND `+fmt.Sprintf(accountVisible, "anchor"), id, user).Scan(&group, &writable)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, errIdentityHidden
	}
	return group, writable, err
}

// lockedIdentity 取组锁后再核对一次，避免与后台重算或其他人工操作交错。
func lockedIdentity(w http.ResponseWriter, r *http.Request, tx *sql.Tx, id uuid.UUID) (uuid.UUID, bool) {
	user := auth.From(r.Context()).ID
	group, _, err := identityAccess(r.Context(), tx, id, user)
	if err == nil {
		err = identity.LockGroup(r.Context(), tx, group)
	}
	var writable bool
	if err == nil {
		group, writable, err = identityAccess(r.Context(), tx, id, user)
	}
	switch {
	case errors.Is(err, errIdentityHidden):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, "身份查询失败", http.StatusInternalServerError)
	case !writable:
		http.Error(w, "无组内权限", http.StatusForbidden)
	default:
		return group, true
	}
	return uuid.Nil, false
}

func auditIdentity(r *http.Request, tx *sql.Tx, action, target, detail string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(id,ts,username,action,target,detail,remote_addr) VALUES($1,now(),$2,$3,$4,$5,$6)`,
		id, auth.From(r.Context()).Username, action, target, detail, audit.RemoteAddr(r))
	return err
}

// decideCandidate 把账号挂到身份 {id}（confirm）或记下「不是同一人」（reject）。
// 只接受当前仍成立的候选，过时的请求返回 409，不按请求里的描述硬写。
func decideCandidate(db *sql.DB, w http.ResponseWriter, r *http.Request, confirm bool) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		AccountID uuid.UUID `json:"accountId"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || body.AccountID == uuid.Nil {
		http.Error(w, "accountId 无效", http.StatusBadRequest)
		return
	}
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "开启事务失败", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	group, ok := lockedIdentity(w, r, tx, id)
	if !ok {
		return
	}
	candidates, err := queryCandidates(r.Context(), tx, id, group, &body.AccountID)
	if err != nil {
		http.Error(w, "合并候选查询失败", http.StatusInternalServerError)
		return
	}
	var candidate *identityCandidateRow
	for i := range candidates {
		if candidates[i].ToIdentityID == id {
			candidate = &candidates[i]
			break
		}
	}
	if candidate == nil {
		http.Error(w, "该账号已不是此身份的合并候选", http.StatusConflict)
		return
	}
	user := auth.From(r.Context()).Username
	name := "SID " + deref(candidate.Account.SID)
	if candidate.Account.Name != nil {
		name = *candidate.Account.Name
	}
	var created uuid.UUID
	if !confirm {
		if candidate.RejectionID != nil {
			http.Error(w, "该候选已被拒绝", http.StatusConflict)
			return
		}
		err = tx.QueryRowContext(r.Context(), `INSERT INTO identity_candidate_rejections(group_id,identity_id,account_id,created_by) VALUES($1,$2,$3,$4) RETURNING id`,
			group, id, body.AccountID, user).Scan(&created)
		if err == nil {
			err = auditIdentity(r, tx, "identity_candidate_rejected", created.String(),
				fmt.Sprintf("账号 %s（%s）不并入身份 %s，依据 %s", name, body.AccountID, id, candidate.Reason))
		}
	} else {
		if candidate.RejectionID != nil {
			http.Error(w, "该候选已被拒绝，请先撤销拒绝", http.StatusConflict)
			return
		}
		var previousLink, previousIdentity uuid.UUID
		err = tx.QueryRowContext(r.Context(), `UPDATE identity_links SET revoked_at=clock_timestamp(),revoked_by=$2,revoke_reason='manual_merge'
 WHERE account_id=$1 AND revoked_at IS NULL AND basis='host_local' RETURNING id,identity_id`, body.AccountID, user).Scan(&previousLink, &previousIdentity)
		if err == nil {
			err = tx.QueryRowContext(r.Context(), `INSERT INTO identity_links(group_id,identity_id,account_id,basis,confidence,evidence,source)
 VALUES($1,$2,$3,'manual','manual',jsonb_build_object('rule','human_confirmed','candidateReason',$4::text,'matchedAccountId',$5::uuid,
  'matchedName',$6::text,'previousIdentityId',$7::uuid,'previousLinkId',$8::uuid),$9) RETURNING id`,
				group, id, body.AccountID, candidate.Reason, candidate.MatchedID, candidate.MatchedName, previousIdentity, previousLink, "user:"+user).Scan(&created)
		}
		if err == nil {
			err = auditIdentity(r, tx, "identity_link_confirmed", created.String(),
				fmt.Sprintf("账号 %s（%s）并入身份 %s，依据 %s；原链接 %s 已撤销", name, body.AccountID, id, candidate.Reason, previousLink))
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]uuid.UUID{"id": created})
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// revokeManualLink 撤销人工确认的链接，账号随即按强证据回到默认归属。系统链接不能人工撤销。
func revokeManualLink(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	revokeDecision(db, w, r, id, `SELECT identity_id FROM identity_links WHERE id=$1`, func(tx *sql.Tx, group uuid.UUID, user string) error {
		var account uuid.UUID
		err := tx.QueryRowContext(r.Context(), `UPDATE identity_links SET revoked_at=clock_timestamp(),revoked_by=$2,revoke_reason='manual_revoked'
 WHERE id=$1 AND revoked_at IS NULL AND basis='manual' RETURNING account_id`, id, user).Scan(&account)
		if err != nil {
			return err
		}
		if err := identity.ReconcileGroup(r.Context(), tx, group); err != nil {
			return err
		}
		return auditIdentity(r, tx, "identity_link_revoked", id.String(), fmt.Sprintf("撤销账号 %s 的人工链接，回到默认归属", account))
	})
}

// revokeRejection 撤销「不是同一人」的判定，候选重新出现。
func revokeRejection(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	revokeDecision(db, w, r, id, `SELECT identity_id FROM identity_candidate_rejections WHERE id=$1`, func(tx *sql.Tx, _ uuid.UUID, user string) error {
		var account uuid.UUID
		err := tx.QueryRowContext(r.Context(), `UPDATE identity_candidate_rejections SET revoked_at=clock_timestamp(),revoked_by=$2
 WHERE id=$1 AND revoked_at IS NULL RETURNING account_id`, id, user).Scan(&account)
		if err != nil {
			return err
		}
		return auditIdentity(r, tx, "identity_candidate_rejection_revoked", id.String(), fmt.Sprintf("撤销对账号 %s 的拒绝", account))
	})
}

func revokeDecision(db *sql.DB, w http.ResponseWriter, r *http.Request, id uuid.UUID, owner string, apply func(*sql.Tx, uuid.UUID, string) error) {
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "开启事务失败", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	var identityID uuid.UUID
	err = tx.QueryRowContext(r.Context(), owner, id).Scan(&identityID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "查询失败", http.StatusInternalServerError)
		return
	}
	group, ok := lockedIdentity(w, r, tx, identityID)
	if !ok {
		return
	}
	err = apply(tx, group, auth.From(r.Context()).Username)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "记录已撤销或不可撤销", http.StatusConflict)
		return
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "撤销失败", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
