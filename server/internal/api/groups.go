package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/ent/finding"
	entgroup "openxdr/server/ent/group"
	"openxdr/server/ent/groupmember"
	"openxdr/server/ent/hostcredential"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/queryrole"
)

type groupRow struct {
	ID         uuid.UUID `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	Name       string    `json:"name"`
	Role       string    `json:"role"` // 当前用户在组内的有效角色
	AssetCount int       `json:"assetCount"`
}

type memberRow struct {
	UserID   uuid.UUID `json:"userId"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
}

// mapGroups 资产组与组内授权。写操作已被 RBAC 拦成 admin 专属；
// 读操作按组内角色过滤：看不到不属于自己的组。
// queryProvisioner 组查询身份的开通与回收（internal/queryrole）。
type queryProvisioner interface {
	Ensure(context.Context, uuid.UUID) error
	Drop(context.Context, uuid.UUID) error
}

func mapGroups(api *http.ServeMux, db *ent.Client, queries queryProvisioner) {
	api.HandleFunc("GET /api/groups", listGroups(db))
	api.HandleFunc("POST /api/groups", createGroup(db, queries))
	api.HandleFunc("DELETE /api/groups/{id}", deleteGroup(db, queries))
	api.HandleFunc("GET /api/groups/{id}/members", listGroupMembers(db))
	api.HandleFunc("PUT /api/groups/{id}/members/{userId}", setGroupMember(db))
	api.HandleFunc("DELETE /api/groups/{id}/members/{userId}", removeGroupMember(db))
	api.HandleFunc("PUT /api/groups/{id}/assets/{assetId}", groupAsset(db))
	api.HandleFunc("DELETE /api/groups/{id}/assets/{assetId}", ungroupAsset(db))
}

// listGroups 当前用户能看到的组；非 admin 只看自己所在的组。
func listGroups(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		q := db.Group.Query()
		if u.Role != "admin" {
			members, err := db.GroupMember.Query().Where(groupmember.UserIDEQ(u.ID)).All(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ids := make([]uuid.UUID, len(members))
			for i, m := range members {
				ids[i] = m.GroupID
			}
			q = q.Where(entgroup.IDIn(ids...))
		}
		groups, err := q.Order(ent.Asc(entgroup.FieldName)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]groupRow, len(groups))
		for i, g := range groups {
			n, err := db.Asset.Query().Where(entasset.GroupIDEQ(g.ID)).Count(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out[i] = groupRow{g.ID, g.CreatedAt, g.Name, auth.GroupRole(r.Context(), db, u, g.ID), n}
		}
		writeJSON(w, out)
	}
}

// createGroup 新建组并带上默认高风险命令名单，顺带开通组查询身份。
func createGroup(db *ent.Client, queries queryProvisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
			http.Error(w, "name 必填", http.StatusBadRequest)
			return
		}
		// 新组自带 AI 高风险命令名单，建好就有基本防护，不用先去配名单
		var g *ent.Group
		err := withTx(r, db, func(tx *ent.Tx) error {
			var err error
			if g, err = tx.Group.Create().SetName(body.Name).Save(r.Context()); err != nil {
				return err
			}
			return commandgate.SeedDefaults(r.Context(), tx.Client(), g.ID)
		})
		if ent.IsConstraintError(err) {
			http.Error(w, "组名已存在", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "group_created", g.ID.String(), fmt.Sprintf("%s（默认高风险名单 %d 条）", g.Name, len(commandgate.DefaultAIDeny)))
		// 查询身份开通失败不影响建组：没权限时退回手工开通，其余错误下次启动补齐
		if queries != nil {
			if err := queries.Ensure(r.Context(), g.ID); err != nil && !errors.Is(err, queryrole.ErrNotAllowed) {
				slog.Error("开通组查询身份失败", "group", g.ID, "err", err)
			}
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, groupRow{g.ID, g.CreatedAt, g.Name, "admin", 0})
	}
}

// deleteGroup 删组：资产退回未分组、成员关系一并清掉，主机本身不受影响
func deleteGroup(db *ent.Client, queries queryProvisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		err := withTx(r, db, func(tx *ent.Tx) error {
			if _, err := tx.HostCredential.Delete().Where(hostcredential.GroupIDEQ(g.ID)).Exec(r.Context()); err != nil {
				return err
			}
			if err := tx.Asset.Update().Where(entasset.GroupIDEQ(g.ID)).ClearGroupID().Exec(r.Context()); err != nil {
				return err
			}
			if _, err := tx.GroupMember.Delete().Where(groupmember.GroupIDEQ(g.ID)).Exec(r.Context()); err != nil {
				return err
			}
			if _, err := tx.CommandPolicy.Delete().Where(commandpolicy.GroupIDEQ(g.ID)).Exec(r.Context()); err != nil {
				return err
			}
			if _, err := tx.Finding.Delete().Where(finding.GroupIDEQ(g.ID)).Exec(r.Context()); err != nil {
				return err
			}
			return tx.Group.DeleteOneID(g.ID).Exec(r.Context())
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if queries != nil {
			if err := queries.Drop(r.Context(), g.ID); err != nil {
				slog.Error("回收组查询身份失败", "group", g.ID, "err", err)
			}
		}
		audit.Log(r.Context(), db, r, "group_deleted", g.ID.String(), g.Name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// listGroupMembers 成员名单只给组 admin 看
func listGroupMembers(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		if !auth.Allowed(auth.GroupRole(r.Context(), db, auth.From(r.Context()), g.ID), "admin") {
			http.Error(w, "当前角色无此权限", http.StatusForbidden)
			return
		}
		members, err := db.GroupMember.Query().Where(groupmember.GroupIDEQ(g.ID)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]memberRow, 0, len(members))
		for _, m := range members {
			u, err := db.User.Get(r.Context(), m.UserID)
			if err != nil {
				continue // 用户已删，成员记录随删号清理，这里不该出现
			}
			out = append(out, memberRow{m.UserID, u.Username, m.Role})
		}
		writeJSON(w, out)
	}
}

// setGroupMember 设定成员角色：不存在就加，存在就改
func setGroupMember(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		u, ok := userFromPath(w, r, db)
		if !ok {
			return
		}
		var body struct {
			Role string `json:"role"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !auth.ValidRole(body.Role) {
			http.Error(w, "role 必须是 admin / analyst / viewer", http.StatusBadRequest)
			return
		}
		n, err := db.GroupMember.Update().
			Where(groupmember.GroupIDEQ(g.ID), groupmember.UserIDEQ(u.ID)).
			SetRole(body.Role).
			Save(r.Context())
		if err == nil && n == 0 {
			err = db.GroupMember.Create().SetGroupID(g.ID).SetUserID(u.ID).SetRole(body.Role).Exec(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "group_member_set", g.Name, u.Username+" → "+body.Role)
		w.WriteHeader(http.StatusNoContent)
	}
}

// removeGroupMember 把用户移出组。
func removeGroupMember(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		u, ok := userFromPath(w, r, db)
		if !ok {
			return
		}
		if _, err := db.GroupMember.Delete().
			Where(groupmember.GroupIDEQ(g.ID), groupmember.UserIDEQ(u.ID)).
			Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "group_member_removed", g.Name, u.Username)
		w.WriteHeader(http.StatusNoContent)
	}
}

// groupAsset 资产归组：一台主机只属于一个组，归入新组即离开旧组
func groupAsset(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		a, ok := assetFromPath(w, r, db)
		if !ok {
			return
		}
		if err := withTx(r, db, func(tx *ent.Tx) error {
			if a.GroupID == nil || *a.GroupID != g.ID {
				if _, err := tx.HostCredential.Delete().Where(hostcredential.AssetIDEQ(a.ID)).Exec(r.Context()); err != nil {
					return err
				}
				// 待办归原组的运维，换组后不再跟着走
				if _, err := tx.Finding.Delete().Where(finding.AssetIDEQ(a.ID)).Exec(r.Context()); err != nil {
					return err
				}
			}
			return tx.Asset.UpdateOneID(a.ID).SetGroupID(g.ID).Exec(r.Context())
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "asset_grouped", a.Hostname, g.Name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ungroupAsset 把资产移出组，退回未分组。
func ungroupAsset(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g, ok := groupFromPath(w, r, db)
		if !ok {
			return
		}
		a, ok := assetFromPath(w, r, db)
		if !ok {
			return
		}
		// 只移出本组的资产，防止拿错组 id 把别组的主机踢成未分组
		n := 0
		err := withTx(r, db, func(tx *ent.Tx) error {
			var err error
			n, err = tx.Asset.Update().Where(entasset.IDEQ(a.ID), entasset.GroupIDEQ(g.ID)).ClearGroupID().Save(r.Context())
			if err != nil || n == 0 {
				return err
			}
			if _, err = tx.HostCredential.Delete().Where(hostcredential.AssetIDEQ(a.ID)).Exec(r.Context()); err != nil {
				return err
			}
			_, err = tx.Finding.Delete().Where(finding.AssetIDEQ(a.ID)).Exec(r.Context())
			return err
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			http.Error(w, "该资产不在此组", http.StatusConflict)
			return
		}
		audit.Log(r.Context(), db, r, "asset_ungrouped", a.Hostname, g.Name)
		w.WriteHeader(http.StatusNoContent)
	}
}

func groupFromPath(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.Group, bool) {
	return getByPath(w, r, "id", "group", db.Group.Get)
}

func userFromPath(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.User, bool) {
	return getByPath(w, r, "userId", "user", db.User.Get)
}

func assetFromPath(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.Asset, bool) {
	return getByPath(w, r, "assetId", "asset", db.Asset.Get)
}

// getByPath 解析路径里的 UUID 并取实体；失败时已写好 400 / 404 / 500。
func getByPath[T any](w http.ResponseWriter, r *http.Request, param, what string, get func(context.Context, uuid.UUID) (T, error)) (T, bool) {
	var zero T
	id, err := uuid.Parse(r.PathValue(param))
	if err != nil {
		http.Error(w, "无效的 "+what+" id", http.StatusBadRequest)
		return zero, false
	}
	v, err := get(r.Context(), id)
	if ent.IsNotFound(err) {
		http.NotFound(w, r)
		return zero, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return zero, false
	}
	return v, true
}

func withTx(r *http.Request, db *ent.Client, fn func(*ent.Tx) error) error {
	tx, err := db.Tx(r.Context())
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
