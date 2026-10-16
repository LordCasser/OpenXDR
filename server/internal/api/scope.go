package api

import (
	"context"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entcommand "openxdr/server/ent/command"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/groupmember"
	entincident "openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/auth"
)

// scope 当前用户在某档角色下能触达的资产。全局 admin 不受限；其余用户只覆盖
// 自己在组内角色够格的那些组的资产。未分组资产与无归属的数据（syslog 等）只有 admin 能碰。
// 各 Where 谓词返回切片，admin 时为空，直接展开进查询。
type scope struct {
	all    bool
	assets []uuid.UUID
}

func scopeOf(ctx context.Context, db *ent.Client, min string) (scope, error) {
	u := auth.From(ctx)
	if u.Role == "admin" {
		return scope{all: true}, nil
	}
	members, err := db.GroupMember.Query().Where(groupmember.UserIDEQ(u.ID)).All(ctx)
	if err != nil {
		return scope{}, err
	}
	var groups []uuid.UUID
	for _, m := range members {
		if auth.Allowed(m.Role, min) {
			groups = append(groups, m.GroupID)
		}
	}
	ids, err := db.Asset.Query().Where(entasset.GroupIDIn(groups...)).IDs(ctx)
	return scope{assets: ids}, err
}

// requireScope 取作用域，失败时已写好 500。
func requireScope(w http.ResponseWriter, r *http.Request, db *ent.Client, min string) (scope, bool) {
	s, err := scopeOf(r.Context(), db, min)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return s, err == nil
}

func (s scope) has(id uuid.UUID) bool { return s.all || slices.Contains(s.assets, id) }

func (s scope) asset() []predicate.Asset {
	if s.all {
		return nil
	}
	return []predicate.Asset{entasset.IDIn(s.assets...)}
}

func (s scope) event() []predicate.Event {
	if s.all {
		return nil
	}
	return []predicate.Event{entevent.AssetIDIn(s.assets...)}
}

func (s scope) alert() []predicate.Alert {
	if s.all {
		return nil
	}
	return []predicate.Alert{entalert.AssetIDIn(s.assets...)}
}

func (s scope) command() []predicate.Command {
	if s.all {
		return nil
	}
	return []predicate.Command{entcommand.AssetIDIn(s.assets...)}
}

// incident 关联可能跨组：只有全部告警都落在作用域内才可见，
// 否则关系图会把别组主机、进程漏给无权的人。
func (s scope) incident() []predicate.Incident {
	if s.all {
		return nil
	}
	return []predicate.Incident{
		entincident.HasAlerts(),
		entincident.Not(entincident.HasAlertsWith(
			entalert.Or(entalert.AssetIDIsNil(), entalert.AssetIDNotIn(s.assets...)))),
	}
}

// incidentVisible 单个 incident 的作用域检查。
func incidentVisible(w http.ResponseWriter, r *http.Request, db *ent.Client, id uuid.UUID, min string) bool {
	s, ok := requireScope(w, r, db, min)
	if !ok || s.all {
		return ok // 不受限时交给后续查询自己报 404
	}
	n, err := db.Incident.Query().Where(entincident.IDEQ(id)).Where(s.incident()...).Count(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if n == 0 {
		deny(w, r, min)
	}
	return n > 0
}

// assetInScope 单个资产的作用域检查。
func assetInScope(w http.ResponseWriter, r *http.Request, db *ent.Client, id uuid.UUID, min string) bool {
	s, ok := requireScope(w, r, db, min)
	if ok && !s.has(id) {
		deny(w, r, min)
		return false
	}
	return ok
}

// deny 作用域外：读按不存在处理，不暴露存在性；写多半是组内角色不够，明说。
func deny(w http.ResponseWriter, r *http.Request, min string) {
	if min == "viewer" {
		http.NotFound(w, r)
		return
	}
	http.Error(w, "当前角色无此权限", http.StatusForbidden)
}
