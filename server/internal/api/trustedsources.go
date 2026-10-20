package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
	enttrusted "openxdr/server/ent/trustedsource"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/automation"
)

type trustedSourceRow struct {
	ID             uuid.UUID  `json:"id"`
	CreatedAt      time.Time  `json:"createdAt"`
	GroupID        uuid.UUID  `json:"groupId"`
	Name           string     `json:"name"`
	Reason         *string    `json:"reason"`
	CreatedBy      string     `json:"createdBy"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	KeyFingerprint *string    `json:"keyFingerprint"`
	SourceCIDR     *string    `json:"sourceCidr"`
	LoginUser      *string    `json:"loginUser"`
	MatchedCount   int        `json:"matchedCount"`
	LastMatchedAt  *time.Time `json:"lastMatchedAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
	RevokedBy      *string    `json:"revokedBy"`
}

func toTrustedSourceRow(t *ent.TrustedSource) trustedSourceRow {
	return trustedSourceRow{
		ID: t.ID, CreatedAt: t.CreatedAt, GroupID: t.GroupID, Name: t.Name, Reason: t.Reason, CreatedBy: t.CreatedBy,
		ExpiresAt: t.ExpiresAt, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser,
		MatchedCount: t.MatchedCount, LastMatchedAt: t.LastMatchedAt, RevokedAt: t.RevokedAt, RevokedBy: t.RevokedBy,
	}
}

// automationRef 告警上标注的可信来源：名称与是否高危例外（仍进研判）
type automationRef struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Watch bool      `json:"watch"`
}

// automationNames 可信来源 ID → 名称，告警与事件列表标注来源用
func automationNames(ctx context.Context, db *ent.Client, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := db.TrustedSource.Query().Where(enttrusted.IDIn(ids...)).
		Select(enttrusted.FieldID, enttrusted.FieldName).All(ctx)
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out, err
}

func refOf(a *ent.Alert, names map[uuid.UUID]string) *automationRef {
	if a.AutomationID == nil {
		return nil
	}
	return &automationRef{ID: *a.AutomationID, Name: names[*a.AutomationID], Watch: a.AutomationWatch}
}

// eventAutomation 事件触发的告警里来自可信来源的那条（同一事件的命中都按同一次登录核对，取一条即可）
func eventAutomation(ctx context.Context, db *ent.Client, events []uuid.UUID) (map[uuid.UUID]*automationRef, error) {
	out := map[uuid.UUID]*automationRef{}
	if len(events) == 0 {
		return out, nil
	}
	alerts, err := db.Alert.Query().Where(entalert.EventIDIn(events...), entalert.AutomationIDNotNil()).
		Select(entalert.FieldEventID, entalert.FieldAutomationID, entalert.FieldAutomationWatch).All(ctx)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for _, a := range alerts {
		ids = append(ids, *a.AutomationID)
	}
	names, err := automationNames(ctx, db, ids)
	if err != nil {
		return nil, err
	}
	for _, a := range alerts {
		ref := refOf(a, names)
		// 高危例外优先展示：它仍进研判，比「已放行」更该被看到
		if prev := out[*a.EventID]; prev == nil || (ref.Watch && !prev.Watch) {
			out[*a.EventID] = ref
		}
	}
	return out, nil
}

// trustedCandidate 组内近期核对过出处的 SSH 登录，登记可信来源时从这里挑
type trustedCandidate struct {
	User      string    `json:"user"`
	SrcIP     string    `json:"srcIp"`
	KeyType   *string   `json:"keyType"`
	KeyFP     *string   `json:"keyFingerprint"`
	Logins    int       `json:"logins"`
	Hosts     int       `json:"hosts"`
	LastSeen  time.Time `json:"lastSeen"`
	SourceIDs []string  `json:"trustedSourceIds"`
}

// mapTrustedSources 可信自动化来源：组管理员登记、撤销，组内成员可看。
// 只有人能登记——这是降低检测的操作，Pi 没有对应工具
func mapTrustedSources(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/trusted-sources", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.TrustedSource.Query()
		if !s.all {
			q = q.Where(enttrusted.GroupIDIn(s.groups...))
		}
		if id, err := uuid.Parse(r.URL.Query().Get("groupId")); err == nil {
			q = q.Where(enttrusted.GroupIDEQ(id))
		}
		rows, err := q.Order(ent.Desc(enttrusted.FieldCreatedAt)).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]trustedSourceRow, len(rows))
		for i, t := range rows {
			out[i] = toTrustedSourceRow(t)
		}
		writeJSON(w, out)
	})

	api.HandleFunc("GET /api/trusted-sources/candidates", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, id, "admin") {
			return
		}
		out, err := trustedCandidates(r.Context(), db, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	})

	api.HandleFunc("POST /api/trusted-sources", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID        uuid.UUID `json:"groupId"`
			Name           string    `json:"name"`
			Reason         string    `json:"reason"`
			KeyFingerprint string    `json:"keyFingerprint"`
			SourceCIDR     string    `json:"sourceCidr"`
			LoginUser      string    `json:"loginUser"`
			ExpiresInDays  int       `json:"expiresInDays"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		body.Name, body.Reason = strings.TrimSpace(body.Name), strings.TrimSpace(body.Reason)
		if n := utf8.RuneCountInString(body.Name); n == 0 || n > 100 {
			http.Error(w, "名称须为 1–100 字", http.StatusBadRequest)
			return
		}
		if utf8.RuneCountInString(body.Reason) > 1000 {
			http.Error(w, "说明不超过 1000 字", http.StatusBadRequest)
			return
		}
		if body.ExpiresInDays < 1 || body.ExpiresInDays > automation.MaxDays {
			http.Error(w, fmt.Sprintf("有效期须为 1–%d 天", automation.MaxDays), http.StatusBadRequest)
			return
		}
		c, err := automation.Criteria{KeyFingerprint: body.KeyFingerprint, SourceCIDR: body.SourceCIDR, LoginUser: body.LoginUser}.Normalize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		var row *ent.TrustedSource
		err = withTx(r, db, func(tx *ent.Tx) error {
			create := tx.TrustedSource.Create().SetGroupID(body.GroupID).SetName(body.Name).SetCreatedBy(actor).
				SetExpiresAt(time.Now().AddDate(0, 0, body.ExpiresInDays))
			if body.Reason != "" {
				create.SetReason(body.Reason)
			}
			if c.KeyFingerprint != "" {
				create.SetKeyFingerprint(c.KeyFingerprint)
			}
			if c.SourceCIDR != "" {
				create.SetSourceCidr(c.SourceCIDR)
			}
			if c.LoginUser != "" {
				create.SetLoginUser(c.LoginUser)
			}
			var err error
			if row, err = create.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "trusted_source_created", row.ID.String(),
				fmt.Sprintf("%s 组=%s 指纹=%s 来源=%s 用户=%s 有效期=%d天", body.Name, body.GroupID, c.KeyFingerprint, c.SourceCIDR, c.LoginUser, body.ExpiresInDays))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, toTrustedSourceRow(row))
	})

	// 撤销即时生效（核对时直接查库），记录保留：已挂在它上面的告警还要说得清来源
	api.HandleFunc("POST /api/trusted-sources/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "trusted source", db.TrustedSource.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		actor := auth.From(r.Context()).Username
		err := withTx(r, db, func(tx *ent.Tx) error {
			n, err := tx.TrustedSource.Update().Where(enttrusted.IDEQ(row.ID), enttrusted.RevokedAtIsNil()).
				SetRevokedAt(time.Now()).SetRevokedBy(actor).Save(r.Context())
			if err != nil {
				return err
			}
			if n != 1 {
				return errAlreadyRevoked
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "trusted_source_revoked", row.ID.String(), row.Name)
		})
		if err == errAlreadyRevoked {
			http.Error(w, "已撤销", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

var errAlreadyRevoked = fmt.Errorf("已撤销")

// trustedCandidates 组内近 7 天带 login_session 的成功登录（agent 已核对出处），按登录身份归并，
// 并标出已被哪些生效中的可信来源覆盖。最多看最近 5000 次登录
func trustedCandidates(ctx context.Context, db *ent.Client, group uuid.UUID) ([]trustedCandidate, error) {
	assets, err := db.Asset.Query().Where(entasset.GroupIDEQ(group)).IDs(ctx)
	if err != nil || len(assets) == 0 {
		return []trustedCandidate{}, err
	}
	events, err := db.Event.Query().
		Where(entevent.AssetIDIn(assets...), entevent.ClassUIDEQ(3002), entevent.SourceEQ("agent"),
			entevent.TsGT(time.Now().Add(-7*24*time.Hour)),
			predicate.Event(func(s *sql.Selector) {
				s.Where(sql.P(func(b *sql.Builder) {
					b.WriteString("(").WriteString(s.C(entevent.FieldRaw)).WriteString("->'login_session') IS NOT NULL")
				}))
			})).
		Order(ent.Desc(entevent.FieldTs)).Limit(5000).
		Select(entevent.FieldTs, entevent.FieldAssetID, entevent.FieldRaw).All(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := db.TrustedSource.Query().
		Where(enttrusted.GroupIDEQ(group), enttrusted.RevokedAtIsNil(), enttrusted.ExpiresAtGT(time.Now())).
		Order(ent.Asc(enttrusted.FieldCreatedAt)).All(ctx)
	if err != nil {
		return nil, err
	}
	type key struct{ user, ip, keyType, fp string }
	byKey := map[key]*trustedCandidate{}
	hosts := map[key]map[uuid.UUID]bool{}
	var order []key
	for _, e := range events {
		var raw map[string]any
		if json.Unmarshal(e.Raw, &raw) != nil {
			continue
		}
		login, ok := automation.Session(raw)
		if !ok {
			continue
		}
		ls, _ := raw["login_session"].(map[string]any)
		keyType, _ := ls["key_type"].(string)
		k := key{login.User, login.SrcIP, keyType, login.KeyFP}
		c := byKey[k]
		if c == nil {
			c = &trustedCandidate{User: login.User, SrcIP: login.SrcIP, LastSeen: e.Ts, SourceIDs: []string{}}
			if keyType != "" {
				c.KeyType = &keyType
			}
			if login.KeyFP != "" {
				fp := login.KeyFP
				c.KeyFP = &fp
			}
			for _, t := range sources {
				if (automation.Source{ID: t.ID, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser}).Matches(login) {
					c.SourceIDs = append(c.SourceIDs, t.ID.String())
				}
			}
			byKey[k], hosts[k] = c, map[uuid.UUID]bool{}
			order = append(order, k)
		}
		c.Logins++
		if e.AssetID != nil {
			hosts[k][*e.AssetID] = true
		}
	}
	out := make([]trustedCandidate, 0, len(order))
	for _, k := range order {
		c := byKey[k]
		c.Hosts = len(hosts[k])
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Logins > out[j].Logins })
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}
