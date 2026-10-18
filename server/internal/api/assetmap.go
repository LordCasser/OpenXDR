package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
)

// AssetMapPaths 由 AssetMap 处理的路径，main 逐个挂到总路由上
var AssetMapPaths = []string{"/api/asset-map", "/api/attack-surface", "/api/zones", "/api/zones/",
	"/api/assets/{id}/profile", "/api/assets/{id}/zone", "/api/assets/{id}/annotate", "/api/assets/{id}/services"}

// AssetMap 资产图谱、攻击面、区域定义与资产画像。读按组 viewer；
// 改标注要组 analyst；区域定义与资产的区域指派影响攻击面判定，要组 admin。
// aiEnabled 为 false 时不接受标注请求，图谱与攻击面照常可用。
func AssetMap(db *ent.Client, aiEnabled bool) http.Handler {
	mux := http.NewServeMux()
	groupParam := func(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", http.StatusBadRequest)
			return uuid.Nil, false
		}
		return id, requireGroup(w, r, db, id, "viewer")
	}

	mux.HandleFunc("GET /api/asset-map", func(w http.ResponseWriter, r *http.Request) {
		id, ok := groupParam(w, r)
		if !ok {
			return
		}
		g, err := assetmap.LoadGroup(r.Context(), db, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, g.Graph(time.Now()))
	})

	mux.HandleFunc("GET /api/attack-surface", func(w http.ResponseWriter, r *http.Request) {
		id, ok := groupParam(w, r)
		if !ok {
			return
		}
		g, err := assetmap.LoadGroup(r.Context(), db, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, g.Surface())
	})

	mux.HandleFunc("GET /api/zones", func(w http.ResponseWriter, r *http.Request) {
		id, ok := groupParam(w, r)
		if !ok {
			return
		}
		rows, err := db.Zone.Query().Where(zone.GroupIDEQ(id)).Order(ent.Asc(zone.FieldName)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	})

	mux.HandleFunc("POST /api/zones", func(w http.ResponseWriter, r *http.Request) {
		var body zoneBody
		if !body.decode(w, r) {
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		row, err := db.Zone.Create().SetGroupID(body.GroupID).SetName(body.Name).SetKind(zone.Kind(body.Kind)).SetCidrs(body.Cidrs).Save(r.Context())
		if !zoneSaved(w, err) {
			return
		}
		audit.Log(r.Context(), db, r, "zone_created", row.ID.String(), body.Name+" "+strings.Join(body.Cidrs, ","))
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, row)
	})

	mux.HandleFunc("PUT /api/zones/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "zone", db.Zone.Get)
		if !ok {
			return
		}
		body := zoneBody{GroupID: row.GroupID}
		if !body.decode(w, r) || !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		row, err := row.Update().SetName(body.Name).SetKind(zone.Kind(body.Kind)).SetCidrs(body.Cidrs).Save(r.Context())
		if !zoneSaved(w, err) {
			return
		}
		audit.Log(r.Context(), db, r, "zone_updated", row.ID.String(), body.Name+" "+strings.Join(body.Cidrs, ","))
		writeJSON(w, row)
	})

	mux.HandleFunc("DELETE /api/zones/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "zone", db.Zone.Get)
		if !ok || !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		// 指派到这个区域的资产回到自动划分
		err := withTx(r, db, func(tx *ent.Tx) error {
			if err := tx.Asset.Update().Where(entasset.ZoneIDEQ(row.ID)).ClearZoneID().Exec(r.Context()); err != nil {
				return err
			}
			return tx.Zone.DeleteOneID(row.ID).Exec(r.Context())
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "zone_deleted", row.ID.String(), row.Name)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/assets/{id}/profile", func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok || !assetInScope(w, r, db, a.ID, "viewer") {
			return
		}
		world, err := assetmap.LoadWorld(r.Context(), db)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		facts, err := assetmap.FactsOf(r.Context(), db, world, a)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var listening []assetmap.Listener
		_ = json.Unmarshal(a.Listening, &listening)
		writeJSON(w, map[string]any{
			"zone": facts.Zone, "exposure": facts.Exposure, "cloud": facts.Cloud,
			"listening": listening, "inventoryAt": a.InventoryAt, "services": assetmap.NotesOf(a),
			"outbound": facts.Outbound, "inbound": facts.Inbound, "publicDestinations": facts.PublicDestinations, "public": withPurpose(facts.Public, a.RelationNotes),
			"role": a.Role, "summary": a.Summary, "criticality": a.Criticality, "reason": a.AnnotationReason,
			"relationNotes": a.RelationNotes, "lockedFields": a.LockedFields,
			"annotatedAt": a.AnnotatedAt, "annotateRequestedAt": a.AnnotateRequestedAt, "aiEnabled": aiEnabled,
		})
	})

	// 人改过的字段锁定，AI 不再覆盖；unlock 交还给 AI 并请求重新标注
	mux.HandleFunc("PUT /api/assets/{id}/profile", func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok || !assetInScope(w, r, db, a.ID, "analyst") {
			return
		}
		var body struct {
			Role        *string  `json:"role"`
			Summary     *string  `json:"summary"`
			Criticality *int     `json:"criticality"`
			Unlock      []string `json:"unlock"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		locked := slices.Clone(a.LockedFields)
		lock := func(f string) {
			if !slices.Contains(locked, f) {
				locked = append(locked, f)
			}
		}
		upd := a.Update()
		if body.Role != nil {
			v := strings.TrimSpace(*body.Role)
			if v == "" || len([]rune(v)) > 32 {
				http.Error(w, "角色须为 1-32 字", http.StatusBadRequest)
				return
			}
			upd.SetRole(v)
			lock("role")
		}
		if body.Summary != nil {
			v := strings.TrimSpace(*body.Summary)
			if len([]rune(v)) > 300 {
				http.Error(w, "功能说明不超过 300 字", http.StatusBadRequest)
				return
			}
			upd.SetSummary(v)
			lock("summary")
		}
		if body.Criticality != nil {
			if *body.Criticality < 1 || *body.Criticality > 5 {
				http.Error(w, "重要程度取 1-5", http.StatusBadRequest)
				return
			}
			upd.SetCriticality(*body.Criticality).SetAnnotationReason("人工指定")
			lock("criticality")
		}
		for _, f := range body.Unlock {
			if !slices.Contains(assetmap.Lockable, f) {
				http.Error(w, "unlock 只能是 role / summary / criticality", http.StatusBadRequest)
				return
			}
			locked = slices.DeleteFunc(locked, func(s string) bool { return s == f })
		}
		if len(body.Unlock) > 0 {
			upd.SetAnnotateRequestedAt(time.Now())
		}
		if err := upd.SetLockedFields(locked).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		detail, _ := json.Marshal(body)
		audit.Log(r.Context(), db, r, "asset_profile_updated", a.ID.String(), a.Hostname+" "+string(detail))
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("PUT /api/assets/{id}/zone", func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok {
			return
		}
		if a.GroupID == nil {
			http.Error(w, "未分组资产不能指派区域", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, *a.GroupID, "admin") {
			return
		}
		var body struct {
			ZoneID *uuid.UUID `json:"zoneId"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		upd, detail := a.Update().ClearZoneID(), a.Hostname+" → 自动"
		if body.ZoneID != nil {
			z, err := db.Zone.Get(r.Context(), *body.ZoneID)
			if err != nil || z.GroupID != *a.GroupID {
				http.Error(w, "区域不存在或不属于该组", http.StatusBadRequest)
				return
			}
			upd, detail = a.Update().SetZoneID(z.ID), a.Hostname+" → "+z.Name
		}
		if err := upd.Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "asset_zone_assigned", a.ID.String(), detail)
		w.WriteHeader(http.StatusNoContent)
	})

	// 人工给服务定名与风险，优先级最高；name 为空表示清除，回到 AI 识别或端口推测
	mux.HandleFunc("PUT /api/assets/{id}/services", func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok || !assetInScope(w, r, db, a.ID, "analyst") {
			return
		}
		var body struct {
			Port string `json:"port"`
			Name string `json:"name"`
			Note string `json:"note"`
			Risk string `json:"risk"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		n, err := assetmap.CleanNote(body.Name, body.Note, body.Risk)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n.Source, n.By = "human", auth.From(r.Context()).Username
		if err := assetmap.SetServiceNote(r.Context(), db, a.ID, body.Port, n); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		detail := a.Hostname + " " + body.Port + " → " + n.Name
		if n.Name == "" {
			detail = a.Hostname + " " + body.Port + " 清除"
		}
		audit.Log(r.Context(), db, r, "asset_service_noted", a.ID.String(), detail)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /api/assets/{id}/annotate", func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok || !assetInScope(w, r, db, a.ID, "analyst") {
			return
		}
		if !aiEnabled {
			http.Error(w, "未配置 AI_MODEL，无法标注", http.StatusServiceUnavailable)
			return
		}
		if err := a.Update().SetAnnotateRequestedAt(time.Now()).Exec(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}

type zoneBody struct {
	GroupID uuid.UUID `json:"groupId"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Cidrs   []string  `json:"cidrs"`
}

// decode 校验并规范化：网段统一成网络地址写法，非法的直接拒绝
func (b *zoneBody) decode(w http.ResponseWriter, r *http.Request) bool {
	group := b.GroupID
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(b) != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return false
	}
	if group != uuid.Nil {
		b.GroupID = group // 修改时组不能换
	}
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" || len([]rune(b.Name)) > 64 {
		http.Error(w, "名称须为 1-64 字", http.StatusBadRequest)
		return false
	}
	if zone.KindValidator(zone.Kind(b.Kind)) != nil {
		http.Error(w, "kind 须为 internal / dmz / external / cloud", http.StatusBadRequest)
		return false
	}
	if len(b.Cidrs) > 64 {
		http.Error(w, "网段最多 64 个", http.StatusBadRequest)
		return false
	}
	for i, c := range b.Cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			http.Error(w, "网段格式无效: "+c, http.StatusBadRequest)
			return false
		}
		b.Cidrs[i] = p.Masked().String()
	}
	return true
}

func zoneSaved(w http.ResponseWriter, err error) bool {
	if ent.IsConstraintError(err) {
		http.Error(w, "同名区域已存在", http.StatusConflict)
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

// withPurpose 公网目的地址带上 AI 标注给的用途（事实里不带，免得回灌给模型）
func withPurpose(ds []assetmap.PublicDest, notes map[string]string) []assetmap.PublicDest {
	for i := range ds {
		ds[i].Purpose = notes[ds[i].IP]
	}
	return ds
}
