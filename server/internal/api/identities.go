package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/identity"
)

// 身份图读取：权限按数据库当前角色与组成员关系判定，不采信会话里缓存的角色。
// 主机账号只有其资产当前仍在身份所属组时才可见，换组后旧组看不到、新组也不继承。

const canReadGroup = `EXISTS(SELECT 1 FROM users u WHERE u.id=$%d AND (u.role='admin' OR EXISTS(
 SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=%s AND m.role IN ('viewer','analyst','admin'))))`

const canWriteGroup = `EXISTS(SELECT 1 FROM users u WHERE u.id=$%d AND (u.role='admin' OR (u.role='analyst' AND EXISTS(
 SELECT 1 FROM group_members m WHERE m.user_id=u.id AND m.group_id=%s AND m.role IN ('analyst','admin')))))`

// accountVisible 账号是目录账号，或其资产当前仍在账号所属组。
const accountVisible = `(%[1]s.asset_id IS NULL OR EXISTS(SELECT 1 FROM assets vs WHERE vs.id=%[1]s.asset_id AND vs.group_id=%[1]s.group_id))`

type identitySummary struct {
	ID         uuid.UUID  `json:"id"`
	GroupID    uuid.UUID  `json:"groupId"`
	Kind       string     `json:"kind"`
	AnchorKind string     `json:"anchorKind"`
	Name       *string    `json:"name"`
	SID        *string    `json:"sid"`
	UID        *int64     `json:"uid"`
	AssetID    *uuid.UUID `json:"assetId"`
	Hostname   *string    `json:"hostname"`
	Authority  *string    `json:"authority"`
	CreatedAt  time.Time  `json:"createdAt"`
	Accounts   int        `json:"accounts"`
	Hosts      int        `json:"hosts"`
	LastSeen   *time.Time `json:"lastSeen"`
	Manual     bool       `json:"manual"`
}

type loginStat struct {
	Success int        `json:"success"`
	Failure int        `json:"failure"`
	Last    *time.Time `json:"last"`
	Sources []string   `json:"sources"`
}

type identityAccount struct {
	ID         uuid.UUID       `json:"id"`
	Kind       string          `json:"kind"`
	Name       *string         `json:"name"`
	Domain     *string         `json:"domain"`
	SID        *string         `json:"sid"`
	UID        *int64          `json:"uid"`
	AssetID    *uuid.UUID      `json:"assetId"`
	Hostname   *string         `json:"hostname"`
	Authority  *string         `json:"authority"`
	FirstSeen  time.Time       `json:"firstSeen"`
	LastSeen   time.Time       `json:"lastSeen"`
	LinkID     *uuid.UUID      `json:"linkId"`
	IdentityID *uuid.UUID      `json:"identityId"`
	Basis      *string         `json:"basis"`
	Confidence *string         `json:"confidence"`
	Evidence   json.RawMessage `json:"evidence"`
	Source     *string         `json:"source"`
	LinkedAt   *time.Time      `json:"linkedAt"`
	Logins     *loginStat      `json:"logins"`
}

type identityLinkHistory struct {
	ID           uuid.UUID       `json:"id"`
	AccountID    uuid.UUID       `json:"accountId"`
	AccountKind  string          `json:"accountKind"`
	AccountName  *string         `json:"accountName"`
	AssetID      *uuid.UUID      `json:"assetId"`
	Basis        string          `json:"basis"`
	Confidence   string          `json:"confidence"`
	Evidence     json.RawMessage `json:"evidence"`
	Source       string          `json:"source"`
	CreatedAt    time.Time       `json:"createdAt"`
	RevokedAt    *time.Time      `json:"revokedAt"`
	RevokedBy    *string         `json:"revokedBy"`
	RevokeReason *string         `json:"revokeReason"`
}

type identityCandidateRow struct {
	Account        identityAccount `json:"account"`
	FromIdentityID uuid.UUID       `json:"fromIdentityId"`
	ToIdentityID   uuid.UUID       `json:"toIdentityId"`
	ToName         *string         `json:"toName"`
	ToKind         string          `json:"toKind"`
	ToHostname     *string         `json:"toHostname"`
	MatchedID      uuid.UUID       `json:"matchedAccountId"`
	MatchedName    *string         `json:"matchedName"`
	MatchedKind    string          `json:"matchedKind"`
	Reason         string          `json:"reason"`
	Direction      string          `json:"direction"`
	RejectionID    *uuid.UUID      `json:"rejectionId"`
}

// Identities 身份列表、详情、候选与人工确认/拒绝/撤销。
func Identities(db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/identities", func(w http.ResponseWriter, r *http.Request) { listIdentities(db, w, r) })
	mux.HandleFunc("GET /api/identities/{id}", func(w http.ResponseWriter, r *http.Request) { getIdentity(db, w, r) })
	mux.HandleFunc("GET /api/identities/{id}/candidates", func(w http.ResponseWriter, r *http.Request) { listCandidates(db, w, r) })
	mux.HandleFunc("POST /api/identities/{id}/links", func(w http.ResponseWriter, r *http.Request) { decideCandidate(db, w, r, true) })
	mux.HandleFunc("POST /api/identities/{id}/rejections", func(w http.ResponseWriter, r *http.Request) { decideCandidate(db, w, r, false) })
	mux.HandleFunc("DELETE /api/identity-links/{id}", func(w http.ResponseWriter, r *http.Request) { revokeManualLink(db, w, r) })
	mux.HandleFunc("DELETE /api/identity-rejections/{id}", func(w http.ResponseWriter, r *http.Request) { revokeRejection(db, w, r) })
	mux.HandleFunc("GET /api/assets/{id}/identity-accounts", func(w http.ResponseWriter, r *http.Request) { assetIdentityAccounts(db, w, r) })
	return mux
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil || id == uuid.Nil {
		http.Error(w, name+" 无效", http.StatusBadRequest)
		return uuid.Nil, false
	}
	return id, true
}

// windowParam 解析 hours（默认 def，1–720）。
func windowParam(w http.ResponseWriter, r *http.Request, def int) (time.Time, bool) {
	hours := def
	if value := r.URL.Query().Get("hours"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 720 {
			http.Error(w, "hours 必须为 1 到 720", http.StatusBadRequest)
			return time.Time{}, false
		}
		hours = n
	}
	return time.Now().Add(-time.Duration(hours) * time.Hour), true
}

func listIdentities(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	p := r.URL.Query()
	group, err := uuid.Parse(p.Get("groupId"))
	if err != nil || group == uuid.Nil {
		http.Error(w, "groupId 无效", http.StatusBadRequest)
		return
	}
	kind := p.Get("kind")
	if kind != "" && kind != "directory" && kind != "host" {
		http.Error(w, "kind 只能是 directory 或 host", http.StatusBadRequest)
		return
	}
	q := p.Get("q")
	if len(q) > 256 {
		http.Error(w, "q 过长", http.StatusBadRequest)
		return
	}
	limit, offset := 100, 0
	if value := p.Get("limit"); value != "" {
		if limit, err = strconv.Atoi(value); err != nil || limit < 1 || limit > 200 {
			http.Error(w, "limit 必须为 1 到 200", http.StatusBadRequest)
			return
		}
	}
	if value := p.Get("offset"); value != "" {
		if offset, err = strconv.Atoi(value); err != nil || offset < 0 || offset > 100000 {
			http.Error(w, "offset 无效", http.StatusBadRequest)
			return
		}
	}
	rows, err := db.QueryContext(r.Context(), `SELECT i.id,i.group_id,i.kind,anchor.kind,anchor.name,anchor.sid,anchor.uid,anchor.asset_id,s.hostname,src.authority,i.created_at,
 count(*),count(DISTINCT a.asset_id),max(a.last_seen),bool_or(l.basis='manual')
 FROM identities i JOIN identity_accounts anchor ON anchor.id=i.anchor_account_id
 LEFT JOIN assets s ON s.id=anchor.asset_id
 LEFT JOIN identity_directory_accounts da ON da.id=anchor.directory_account_id LEFT JOIN identity_directory_sources src ON src.id=da.source_id
 JOIN identity_links l ON l.identity_id=i.id AND l.revoked_at IS NULL
 JOIN identity_accounts a ON a.id=l.account_id
 WHERE i.group_id=$1 AND `+fmt.Sprintf(canReadGroup, 2, "i.group_id")+` AND `+fmt.Sprintf(accountVisible, "anchor")+` AND `+fmt.Sprintf(accountVisible, "a")+`
 AND ($3='' OR i.kind=$3)
 AND ($4='' OR EXISTS(SELECT 1 FROM identity_links l2 JOIN identity_accounts a2 ON a2.id=l2.account_id LEFT JOIN assets s2 ON s2.id=a2.asset_id
  WHERE l2.identity_id=i.id AND l2.revoked_at IS NULL AND (strpos(lower(a2.name),lower($4))>0 OR a2.sid=$4 OR strpos(lower(s2.hostname),lower($4))>0)))
 GROUP BY i.id,anchor.id,s.hostname,src.authority
 ORDER BY lower(anchor.name) NULLS LAST,anchor.sid,i.id LIMIT $5 OFFSET $6`, group, u.ID, kind, q, limit+1, offset)
	if err != nil {
		http.Error(w, "身份列表查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	items := make([]identitySummary, 0)
	for rows.Next() {
		var item identitySummary
		if err := rows.Scan(&item.ID, &item.GroupID, &item.Kind, &item.AnchorKind, &item.Name, &item.SID, &item.UID, &item.AssetID, &item.Hostname, &item.Authority,
			&item.CreatedAt, &item.Accounts, &item.Hosts, &item.LastSeen, &item.Manual); err != nil {
			http.Error(w, "身份列表读取失败", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		http.Error(w, "身份列表读取失败", http.StatusInternalServerError)
		return
	}
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}
	writeJSON(w, struct {
		Items     []identitySummary `json:"items"`
		Truncated bool              `json:"truncated"`
	}{items, truncated})
}

// readIdentity 读取可见身份的概要；不可见或不存在都返回 sql.ErrNoRows。
func readIdentity(ctx context.Context, db *sql.DB, id, user uuid.UUID) (identitySummary, error) {
	var item identitySummary
	err := db.QueryRowContext(ctx, `SELECT i.id,i.group_id,i.kind,anchor.kind,anchor.name,anchor.sid,anchor.uid,anchor.asset_id,s.hostname,src.authority,i.created_at
 FROM identities i JOIN identity_accounts anchor ON anchor.id=i.anchor_account_id LEFT JOIN assets s ON s.id=anchor.asset_id
 LEFT JOIN identity_directory_accounts da ON da.id=anchor.directory_account_id LEFT JOIN identity_directory_sources src ON src.id=da.source_id
 WHERE i.id=$1 AND `+fmt.Sprintf(canReadGroup, 2, "i.group_id")+` AND `+fmt.Sprintf(accountVisible, "anchor"), id, user).
		Scan(&item.ID, &item.GroupID, &item.Kind, &item.AnchorKind, &item.Name, &item.SID, &item.UID, &item.AssetID, &item.Hostname, &item.Authority, &item.CreatedAt)
	return item, err
}

const accountColumns = `a.id,a.kind,a.name,a.domain,a.sid,a.uid,a.asset_id,s.hostname,src.authority,a.first_seen,a.last_seen`

const accountJoins = ` LEFT JOIN assets s ON s.id=a.asset_id
 LEFT JOIN identity_directory_accounts da ON da.id=a.directory_account_id LEFT JOIN identity_directory_sources src ON src.id=da.source_id`

func scanAccount(row interface{ Scan(...any) error }, a *identityAccount, extra ...any) error {
	return row.Scan(append([]any{&a.ID, &a.Kind, &a.Name, &a.Domain, &a.SID, &a.UID, &a.AssetID, &a.Hostname, &a.Authority, &a.FirstSeen, &a.LastSeen}, extra...)...)
}

func getIdentity(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	from, ok := windowParam(w, r, 168)
	if !ok {
		return
	}
	item, err := readIdentity(r.Context(), db, id, u.ID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "身份不存在或不可访问", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "身份查询失败", http.StatusInternalServerError)
		return
	}
	accounts, truncated, err := identityAccounts(r.Context(), db, `l.identity_id=$1 AND l.revoked_at IS NULL AND `+fmt.Sprintf(accountVisible, "a"), 500, id)
	if err != nil {
		http.Error(w, "身份账号读取失败", http.StatusInternalServerError)
		return
	}
	if err := attachLoginStats(r.Context(), db, accounts, from); err != nil {
		http.Error(w, "登录统计读取失败", http.StatusInternalServerError)
		return
	}
	history, err := linkHistory(r.Context(), db, id)
	if err != nil {
		http.Error(w, "链接记录读取失败", http.StatusInternalServerError)
		return
	}
	item.Accounts = len(accounts)
	writeJSON(w, struct {
		Identity  identitySummary       `json:"identity"`
		Accounts  []identityAccount     `json:"accounts"`
		Truncated bool                  `json:"truncated"`
		History   []identityLinkHistory `json:"history"`
	}{item, accounts, truncated, history})
}

// identityAccounts 按条件读取带当前链接的账号；where 中 $1 由调用方提供。
func identityAccounts(ctx context.Context, db *sql.DB, where string, limit int, arg any) ([]identityAccount, bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+accountColumns+`,l.id,l.identity_id,l.basis,l.confidence,l.evidence,l.source,l.created_at
 FROM identity_accounts a LEFT JOIN identity_links l ON l.account_id=a.id AND l.revoked_at IS NULL`+accountJoins+`
 WHERE `+where+` ORDER BY a.kind,lower(a.name) NULLS LAST,a.id LIMIT `+strconv.Itoa(limit+1), arg)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]identityAccount, 0)
	for rows.Next() {
		var a identityAccount
		var evidence []byte
		if err := scanAccount(rows, &a, &a.LinkID, &a.IdentityID, &a.Basis, &a.Confidence, &evidence, &a.Source, &a.LinkedAt); err != nil {
			return nil, false, err
		}
		if evidence != nil {
			a.Evidence = evidence
		}
		items = append(items, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(items) > limit {
		return items[:limit], true, nil
	}
	return items, false, nil
}

// attachLoginStats 汇总时间窗口内的登录：Windows 按 (组, 资产, SID) 账号键，
// Linux 只计已关联到该账号（同 UID 与用户名、登录时有效清单）的登录。目录账号本身没有登录遥测。
func attachLoginStats(ctx context.Context, db *sql.DB, accounts []identityAccount, from time.Time) error {
	ids := make([]string, 0, len(accounts))
	index := map[uuid.UUID]int{}
	for i, a := range accounts {
		if a.Kind != "directory" {
			ids = append(ids, a.ID.String())
			index[a.ID] = i
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `WITH acct AS (SELECT * FROM identity_accounts WHERE id=ANY($1::uuid[])),
logins AS (
 SELECT a.id AS account_id,e.ts,o.success,NULLIF(NULLIF(e.raw->'src_endpoint'->>'ip',''),'-') AS addr
 FROM acct a JOIN identity_observations o ON a.kind='windows' AND o.group_id=a.group_id AND o.account_key=a.account_key
 JOIN events e ON e.id=o.event_id WHERE e.ts>=$2 AND o.success IS NOT NULL
 UNION ALL
 SELECT a.id,m.ts,m.success,NULLIF(NULLIF(m.source_address,''),'-') FROM acct a JOIN identity_login_matches m
  ON a.kind='linux' AND m.asset_id=a.asset_id AND m.group_id=a.group_id AND m.state='matched' AND m.uid=a.uid AND m.account_name=a.name
 WHERE m.ts>=$2
), addrs AS (SELECT account_id,addr,max(ts) AS last FROM logins WHERE addr IS NOT NULL GROUP BY 1,2)
SELECT l.account_id,count(*) FILTER (WHERE l.success),count(*) FILTER (WHERE NOT l.success),max(l.ts),
 COALESCE((SELECT jsonb_agg(t.addr ORDER BY t.last DESC) FROM (SELECT addr,last FROM addrs WHERE addrs.account_id=l.account_id ORDER BY last DESC LIMIT 5) t),'[]'::jsonb)
FROM logins l GROUP BY l.account_id`, ids, from)
	if err != nil {
		return err
	}
	defer rows.Close()
	for i := range accounts {
		if accounts[i].Kind != "directory" {
			accounts[i].Logins = &loginStat{Sources: []string{}}
		}
	}
	for rows.Next() {
		var id uuid.UUID
		var stat loginStat
		var last sql.NullTime
		var sources []byte
		if err := rows.Scan(&id, &stat.Success, &stat.Failure, &last, &sources); err != nil {
			return err
		}
		if last.Valid {
			stat.Last = &last.Time
		}
		if err := json.Unmarshal(sources, &stat.Sources); err != nil {
			return err
		}
		accounts[index[id]].Logins = &stat
	}
	return rows.Err()
}

func linkHistory(ctx context.Context, db *sql.DB, id uuid.UUID) ([]identityLinkHistory, error) {
	rows, err := db.QueryContext(ctx, `SELECT l.id,a.id,a.kind,a.name,a.asset_id,l.basis,l.confidence,l.evidence,l.source,l.created_at,l.revoked_at,l.revoked_by,l.revoke_reason
 FROM identity_links l JOIN identity_accounts a ON a.id=l.account_id
 WHERE l.identity_id=$1 AND l.revoked_at IS NOT NULL AND `+fmt.Sprintf(accountVisible, "a")+`
 ORDER BY l.revoked_at DESC,l.id DESC LIMIT 50`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]identityLinkHistory, 0)
	for rows.Next() {
		var h identityLinkHistory
		if err := rows.Scan(&h.ID, &h.AccountID, &h.AccountKind, &h.AccountName, &h.AssetID, &h.Basis, &h.Confidence, &h.Evidence, &h.Source, &h.CreatedAt, &h.RevokedAt, &h.RevokedBy, &h.RevokeReason); err != nil {
			return nil, err
		}
		items = append(items, h)
	}
	return items, rows.Err()
}

// candidateQuery 列出与身份 $1（组 $2）相关的合并候选，两个方向：
// 别的身份里可移动的账号可能属于本身份（incoming），本身份里可移动的账号可能属于别的身份（outgoing）。
// 只有默认主机内归属（host_local）的 Windows/Linux 账号可移动；目录账号、SID 强链接与人工链接不作为候选。
// 依据：同名（大小写不敏感）、相似名（去掉 DOMAIN\ 与 @后缀后相同）、SID 与多个目录账号一致（歧义）。
// $3 非空时只看该账号。
func candidateQuery() string {
	norm := func(column string) string { return fmt.Sprintf(identity.NormName, column) }
	byName := norm("x.name") + `=` + norm("y.name") + ` AND ` + norm("x.name") + `<>''`
	bySID := `x.kind='windows' AND y.kind='directory' AND x.sid=y.sid`
	// 名字与 SID 分开成独立分支，各自走 identity_accounts 上的表达式索引与 SID 索引
	pair := func(direction, where, match string) string {
		return `SELECT x.id AS account_id,xl.identity_id AS from_identity,yl.identity_id AS to_identity,y.id AS matched,
 CASE WHEN x.kind='windows' AND y.kind='directory' AND x.sid=y.sid THEN 'sid_ambiguous'
  WHEN lower(x.name)=lower(y.name) THEN 'same_name' ELSE 'similar_name' END AS reason,'` + direction + `' AS direction
 FROM identity_links yl JOIN identity_accounts y ON y.id=yl.account_id
 JOIN identity_accounts x ON x.group_id=y.group_id AND x.kind IN ('windows','linux') AND x.id<>y.id AND ` + match + `
 JOIN identity_links xl ON xl.account_id=x.id AND xl.revoked_at IS NULL AND xl.basis='host_local' AND xl.identity_id<>yl.identity_id
 WHERE yl.revoked_at IS NULL AND yl.group_id=$2 AND ` + where + ` AND ($3::uuid IS NULL OR x.id=$3)
  AND ` + fmt.Sprintf(accountVisible, "x") + ` AND ` + fmt.Sprintf(accountVisible, "y")
	}
	return `WITH pairs AS (` + pair("incoming", "yl.identity_id=$1", byName) + ` UNION ALL ` + pair("incoming", "yl.identity_id=$1", bySID) +
		` UNION ALL ` + pair("outgoing", "xl.identity_id=$1", byName) + ` UNION ALL ` + pair("outgoing", "xl.identity_id=$1", bySID) + `),
best AS (SELECT DISTINCT ON (account_id,to_identity) * FROM pairs
 ORDER BY account_id,to_identity,CASE reason WHEN 'sid_ambiguous' THEN 0 WHEN 'same_name' THEN 1 ELSE 2 END,matched)
SELECT ` + accountColumns + `,b.from_identity,b.to_identity,anchor.name,ti.kind,ts.hostname,b.matched,y.name,y.kind,b.reason,b.direction,rj.id
 FROM best b JOIN identity_accounts a ON a.id=b.account_id` + accountJoins + `
 JOIN identities ti ON ti.id=b.to_identity JOIN identity_accounts anchor ON anchor.id=ti.anchor_account_id
 LEFT JOIN assets ts ON ts.id=anchor.asset_id JOIN identity_accounts y ON y.id=b.matched
 LEFT JOIN identity_candidate_rejections rj ON rj.identity_id=b.to_identity AND rj.account_id=b.account_id AND rj.revoked_at IS NULL
 WHERE ` + fmt.Sprintf(accountVisible, "anchor") + `
 ORDER BY CASE b.reason WHEN 'sid_ambiguous' THEN 0 WHEN 'same_name' THEN 1 ELSE 2 END,ti.kind,lower(a.name),a.id,b.to_identity LIMIT 51`
}

func queryCandidates(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id, group uuid.UUID, account *uuid.UUID) ([]identityCandidateRow, error) {
	var only any
	if account != nil {
		only = *account
	}
	rows, err := q.QueryContext(ctx, candidateQuery(), id, group, only)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]identityCandidateRow, 0)
	for rows.Next() {
		var c identityCandidateRow
		if err := scanAccount(rows, &c.Account, &c.FromIdentityID, &c.ToIdentityID, &c.ToName, &c.ToKind, &c.ToHostname, &c.MatchedID, &c.MatchedName, &c.MatchedKind, &c.Reason, &c.Direction, &c.RejectionID); err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

func listCandidates(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	item, err := readIdentity(r.Context(), db, id, u.ID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "身份不存在或不可访问", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "身份查询失败", http.StatusInternalServerError)
		return
	}
	items, err := queryCandidates(r.Context(), db, id, item.GroupID, nil)
	if err != nil {
		http.Error(w, "合并候选查询失败", http.StatusInternalServerError)
		return
	}
	truncated := len(items) > 50
	if truncated {
		items = items[:50]
	}
	writeJSON(w, struct {
		Items     []identityCandidateRow `json:"items"`
		Truncated bool                   `json:"truncated"`
	}{items, truncated})
}

type unmatchedLogin struct {
	Name    string    `json:"name"`
	State   string    `json:"state"`
	Success int       `json:"success"`
	Failure int       `json:"failure"`
	Last    time.Time `json:"last"`
	Sources []string  `json:"sources"`
}

// assetIdentityAccounts 资产上登记过的账号及近期登录、所属身份，以及没能关联到账号的 Linux 登录。
func assetIdentityAccounts(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	asset, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	from, ok := windowParam(w, r, 24)
	if !ok {
		return
	}
	var group uuid.NullUUID
	err := db.QueryRowContext(r.Context(), `SELECT s.group_id FROM assets s WHERE s.id=$1 AND s.group_id IS NOT NULL AND `+fmt.Sprintf(canReadGroup, 2, "s.group_id"), asset, u.ID).Scan(&group)
	if errors.Is(err, sql.ErrNoRows) {
		// 未归组资产没有身份图；无权限与不存在一样返回空，不泄露资产是否存在
		writeJSON(w, map[string]any{"accounts": []identityAccount{}, "unmatched": []unmatchedLogin{}, "pending": 0, "truncated": false})
		return
	}
	if err != nil {
		http.Error(w, "资产账号查询失败", http.StatusInternalServerError)
		return
	}
	accounts, truncated, err := identityAccounts(r.Context(), db, `a.asset_id=$1 AND a.group_id=s.group_id`, 1000, asset)
	if err != nil {
		http.Error(w, "资产账号读取失败", http.StatusInternalServerError)
		return
	}
	if err := attachLoginStats(r.Context(), db, accounts, from); err != nil {
		http.Error(w, "登录统计读取失败", http.StatusInternalServerError)
		return
	}
	// 有登录的排前面，最近登录优先
	lastLogin := func(a identityAccount) time.Time {
		if a.Logins == nil || a.Logins.Last == nil {
			return time.Time{}
		}
		return *a.Logins.Last
	}
	sort.SliceStable(accounts, func(i, j int) bool { return lastLogin(accounts[i]).After(lastLogin(accounts[j])) })
	rows, err := db.QueryContext(r.Context(), `WITH m AS (SELECT account_name,state,success,ts,NULLIF(NULLIF(source_address,''),'-') AS addr
 FROM identity_login_matches WHERE asset_id=$1 AND group_id=$2 AND state<>'matched' AND ts>=$3)
SELECT g.account_name,g.state,count(*) FILTER (WHERE g.success),count(*) FILTER (WHERE NOT g.success),max(g.ts),
 COALESCE((SELECT jsonb_agg(t.addr ORDER BY t.last DESC) FROM (SELECT addr,max(ts) AS last FROM m WHERE m.account_name=g.account_name AND m.state=g.state AND addr IS NOT NULL
  GROUP BY addr ORDER BY last DESC LIMIT 5) t),'[]'::jsonb)
FROM m g GROUP BY g.account_name,g.state ORDER BY max(g.ts) DESC LIMIT 100`, asset, group.UUID, from)
	if err != nil {
		http.Error(w, "未关联登录查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	unmatched := make([]unmatchedLogin, 0)
	for rows.Next() {
		var row unmatchedLogin
		var sources []byte
		if err := rows.Scan(&row.Name, &row.State, &row.Success, &row.Failure, &row.Last, &sources); err != nil || json.Unmarshal(sources, &row.Sources) != nil {
			http.Error(w, "未关联登录读取失败", http.StatusInternalServerError)
			return
		}
		unmatched = append(unmatched, row)
	}
	if rows.Err() != nil {
		http.Error(w, "未关联登录读取失败", http.StatusInternalServerError)
		return
	}
	// 后台每分钟关联一次，尚未处理的登录单独计数，不当作未匹配
	var pending int
	if err := db.QueryRowContext(r.Context(), `SELECT count(*) FROM identity_observations o JOIN events e ON e.id=o.event_id
 WHERE o.asset_id=$1 AND o.group_id=$2 AND o.state='missing_uid' AND e.ts>=$3
 AND NOT EXISTS(SELECT 1 FROM identity_login_matches m WHERE m.event_id=o.event_id)`, asset, group.UUID, from).Scan(&pending); err != nil {
		http.Error(w, "待关联登录查询失败", http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		Accounts  []identityAccount `json:"accounts"`
		Unmatched []unmatchedLogin  `json:"unmatched"`
		Pending   int               `json:"pending"`
		Truncated bool              `json:"truncated"`
	}{accounts, unmatched, pending, truncated})
}
