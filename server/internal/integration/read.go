package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
)

type cursor struct {
	After   uuid.UUID `json:"after"`
	Binding string    `json:"binding"`
	Expires int64     `json:"expires"`
}

func (s *Service) signCursor(c cursor) string {
	body, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, s.CursorKey)
	mac.Write(body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *Service) parseCursor(value, binding string) (uuid.UUID, error) {
	if len(value) > 2048 {
		return uuid.Nil, errors.New("cursor 过长")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return uuid.Nil, errors.New("cursor 无效")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return uuid.Nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return uuid.Nil, err
	}
	mac := hmac.New(sha256.New, s.CursorKey)
	mac.Write(body)
	var c cursor
	if !hmac.Equal(signature, mac.Sum(nil)) || json.Unmarshal(body, &c) != nil || c.Binding != binding || c.Expires <= time.Now().Unix() {
		return uuid.Nil, errors.New("cursor 已失效，请重新分页")
	}
	return c.After, nil
}
func binding(r *http.Request, p principal) string {
	q := r.URL.Query()
	q.Del("cursor")
	groups := slices.Clone(p.Groups)
	slices.SortFunc(groups, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	raw, _ := json.Marshal([]any{r.URL.Path, q.Encode(), p.Integration.ID, p.Token.ID, p.Integration.PermissionVersion, p.Integration.Scopes, p.Token.Scopes, groups})
	return TokenHash(string(raw))
}
func (s *Service) page(w http.ResponseWriter, r *http.Request, allowed ...string) (int, uuid.UUID, string, bool) {
	q := r.URL.Query()
	for k, values := range q {
		if len(values) != 1 || (!slices.Contains(allowed, k) && k != "limit" && k != "cursor") {
			Error(w, 400, "invalid_argument", "未知或重复查询参数")
			return 0, uuid.Nil, "", false
		}
	}
	limit := 100
	if value := q.Get("limit"); value != "" {
		var err error
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 500 {
			Error(w, 400, "invalid_argument", "limit 必须为 1–500")
			return 0, uuid.Nil, "", false
		}
	}
	b := binding(r, r.Context().Value(principalKey{}).(principal))
	after := uuid.Nil
	if v := q.Get("cursor"); v != "" {
		var err error
		after, err = s.parseCursor(v, b)
		if err != nil {
			Error(w, 400, "invalid_cursor", "游标无效或授权已变化，请重新分页")
			return 0, uuid.Nil, "", false
		}
	}
	return limit, after, b, true
}
func (s *Service) respondPage(w http.ResponseWriter, items any, more bool, last uuid.UUID, b string) {
	var next *string
	if more {
		v := s.signCursor(cursor{last, b, time.Now().Add(time.Hour).Unix()})
		next = &v
	}
	JSON(w, 200, map[string]any{"items": items, "hasMore": more, "nextCursor": next, "observedAt": time.Now().UTC()})
}

type assetRow struct {
	ID            uuid.UUID  `json:"id"`
	Hostname      string     `json:"hostname"`
	OS            *string    `json:"os"`
	OSDisplay     *string    `json:"osDisplay"`
	IPAddrs       []string   `json:"ipAddrs"`
	GroupID       *uuid.UUID `json:"groupId"`
	AgentID       *uuid.UUID `json:"agentId"`
	AgentVersion  *string    `json:"agentVersion"`
	SensorVersion *string    `json:"sensorVersion"`
	FirstSeen     time.Time  `json:"firstSeen"`
	LastSeen      time.Time  `json:"lastSeen"`
	SensorSeen    *time.Time `json:"sensorSeen"`
}

func assetDTO(a *ent.Asset) assetRow {
	return assetRow{a.ID, a.Hostname, a.Os, a.OsDisplay, a.IPAddrs, a.GroupID, a.AgentID, a.AgentVersion, a.SensorVersion, a.FirstSeen, a.LastSeen, a.SensorSeen}
}
func (s *Service) assets(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	q := s.DB.Asset.Query().Where(asset.GroupIDIn(p.Groups...))
	if id := r.PathValue("id"); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			Error(w, 404, "not_found", "资产不存在")
			return
		}
		a, err := q.Where(asset.IDEQ(parsed)).Only(r.Context())
		if readError(w, err) {
			return
		}
		JSON(w, 200, assetDTO(a))
		return
	}
	limit, after, b, ok := s.page(w, r, "q", "groupId")
	if !ok {
		return
	}
	if after != uuid.Nil {
		q.Where(asset.IDGT(after))
	}
	if id := r.URL.Query().Get("groupId"); id != "" {
		g, err := uuid.Parse(id)
		if err != nil {
			Error(w, 400, "invalid_argument", "groupId 无效")
			return
		}
		q.Where(asset.GroupIDEQ(g))
	}
	if v := r.URL.Query().Get("q"); v != "" {
		if len(v) > 1000 {
			Error(w, 400, "invalid_argument", "搜索内容过长")
			return
		}
		q.Where(asset.Or(asset.HostnameContainsFold(v), func(s *sql.Selector) {
			s.Where(sql.P().Append(func(b *sql.Builder) {
				b.WriteString("EXISTS (SELECT 1 FROM jsonb_array_elements_text(").Ident(s.C(asset.FieldIPAddrs)).WriteString(") AS ip(value) WHERE strpos(ip.value, ").Arg(v).WriteString(") > 0)")
			}))
		}))
	}
	rows, err := q.Order(ent.Asc(asset.FieldID)).Limit(limit + 1).All(r.Context())
	if readError(w, err) {
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]assetRow, 0, len(rows))
	last := uuid.Nil
	for _, a := range rows {
		out = append(out, assetDTO(a))
		last = a.ID
	}
	s.respondPage(w, out, more, last, b)
}

func incidentScope(groups []uuid.UUID) []predicate.Incident {
	return []predicate.Incident{
		incident.HasAlerts(), incident.Not(incident.HasAlertsWith(alert.Not(alert.HasAssetWith(asset.GroupIDIn(groups...))))),
	}
}

type incidentRow struct {
	Revision   int64      `json:"revision"`
	ID         uuid.UUID  `json:"id"`
	CreatedAt  time.Time  `json:"createdAt"`
	Status     string     `json:"status"`
	Title      *string    `json:"title"`
	Resolution *string    `json:"resolution"`
	ResolvedBy *string    `json:"resolvedBy"`
	ResolvedAt *time.Time `json:"resolvedAt"`
}

func incidentDTO(i *ent.Incident) incidentRow {
	return incidentRow{i.IntegrationRevision, i.ID, i.CreatedAt, i.Status, i.Title, i.Resolution, i.ResolvedBy, i.ResolvedAt}
}
func timeFilter(q url.Values, key string) (*time.Time, error) {
	v := q.Get(key)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	return &t, err
}
func (s *Service) incidents(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	q := s.DB.Incident.Query().Where(incidentScope(p.Groups)...)
	if id := r.PathValue("id"); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			Error(w, 404, "not_found", "事件不存在")
			return
		}
		row, err := q.Where(incident.IDEQ(parsed)).Only(r.Context())
		if readError(w, err) {
			return
		}
		JSON(w, 200, incidentDTO(row))
		return
	}
	limit, after, b, ok := s.page(w, r, "status", "createdFrom", "createdTo")
	if !ok {
		return
	}
	if after != uuid.Nil {
		q.Where(incident.IDGT(after))
	}
	v := r.URL.Query()
	if status := v.Get("status"); status != "" {
		if !slices.Contains([]string{"open", "triaged", "closed", "false_positive"}, status) {
			Error(w, 400, "invalid_argument", "status 无效")
			return
		}
		q.Where(incident.StatusEQ(status))
	}
	from, e1 := timeFilter(v, "createdFrom")
	to, e2 := timeFilter(v, "createdTo")
	if e1 != nil || e2 != nil || (from != nil && to != nil && !from.Before(*to)) {
		Error(w, 400, "invalid_argument", "创建时间范围无效")
		return
	}
	if from != nil {
		q.Where(incident.CreatedAtGTE(*from))
	}
	if to != nil {
		q.Where(incident.CreatedAtLT(*to))
	}
	rows, err := q.Order(ent.Asc(incident.FieldID)).Limit(limit + 1).All(r.Context())
	if readError(w, err) {
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]incidentRow, 0, len(rows))
	last := uuid.Nil
	for _, i := range rows {
		out = append(out, incidentDTO(i))
		last = i.ID
	}
	s.respondPage(w, out, more, last, b)
}
func readError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if ent.IsNotFound(err) {
		Error(w, 404, "not_found", "资源不存在")
	} else {
		Error(w, 503, "unavailable", "查询暂不可用")
	}
	return true
}
