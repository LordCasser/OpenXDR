package hostimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/group"
	"openxdr/server/ent/hostcredential"
	"openxdr/server/internal/triage"
)

type Service struct {
	LLM       *triage.LLM
	VisionLLM *triage.LLM
	DB        *ent.Client
	Vault     *Vault
}

func binding(c *ent.HostCredential) string {
	// 同时绑定连接目标和身份，数据库内调换地址、用户名或指纹也无法把凭据用于另一目标。
	data, _ := json.Marshal([]any{"host-credential:v1", c.ID, c.AssetID, c.GroupID, c.Address, c.Port, c.Username, c.Kind, c.HostKey})
	return string(data)
}

// Import 整批原子提交，不覆盖已有资产或凭据；冲突需用户核对，禁止通过导入改组。
func (s *Service) Import(ctx context.Context, groupID uuid.UUID, hosts []Host) ([]uuid.UUID, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if ok, err := tx.Group.Query().Where(group.IDEQ(groupID)).Exist(ctx); err != nil || !ok {
		return nil, errors.New("组不存在")
	}
	ids := make([]uuid.UUID, 0, len(hosts))
	for i, h := range hosts {
		a, err := tx.Asset.Query().Where(asset.HostnameEQ(h.Hostname)).Only(ctx)
		if ent.IsNotFound(err) {
			create := tx.Asset.Create().SetHostname(h.Hostname).SetOs(h.OS).SetGroupID(groupID).SetLastSeen(time.Unix(0, 0))
			if h.OSDisplay != "" {
				create = create.SetOsDisplay(h.OSDisplay)
			}
			if net.ParseIP(h.Address) != nil {
				create.SetIPAddrs([]string{h.Address})
			}
			a, err = create.Save(ctx)
		} else if err == nil && (a.GroupID == nil || *a.GroupID != groupID) {
			return nil, fmt.Errorf("第 %d 条主机已属于其他组或未分组", i+1)
		}
		if err != nil {
			return nil, err
		}
		if a.Os == nil || *a.Os == "" {
			update := tx.Asset.UpdateOne(a).SetOs(h.OS)
			if h.OSDisplay != "" {
				update = update.SetOsDisplay(h.OSDisplay)
			}
			a, err = update.Save(ctx)
			if err != nil {
				return nil, err
			}
		} else if *a.Os != h.OS {
			return nil, fmt.Errorf("第 %d 条主机系统与已有资产不一致", i+1)
		}
		if h.Kind != "none" {
			exists, err := tx.HostCredential.Query().Where(hostcredential.AssetIDEQ(a.ID)).Exist(ctx)
			if err != nil {
				return nil, err
			}
			if exists {
				return nil, fmt.Errorf("第 %d 条主机已有凭据，请先删除旧凭据再导入", i+1)
			}
		}
		ids = append(ids, a.ID)
		if h.Kind == "none" {
			continue
		}
		id := uuid.New()
		metadata := &ent.HostCredential{ID: id, AssetID: a.ID, GroupID: groupID, Address: h.Address, Port: h.Port, Username: h.Username, Kind: h.Kind, HostKey: h.HostKey}
		sealed, err := s.Vault.Seal(h.Secret, binding(metadata))
		if err != nil {
			return nil, err
		}
		if err = tx.HostCredential.Create().SetID(id).SetAssetID(a.ID).SetGroupID(groupID).
			SetAddress(h.Address).SetPort(h.Port).SetUsername(h.Username).SetKind(h.Kind).
			SetHostKey(h.HostKey).SetSealed(sealed).Exec(ctx); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

// Credential 仅供受授权的连接操作使用；每次检查资产仍属于保存凭据时的组。
func (s *Service) Credential(ctx context.Context, id, groupID uuid.UUID) (*ent.HostCredential, Secret, error) {
	c, err := s.DB.HostCredential.Query().Where(hostcredential.IDEQ(id), hostcredential.GroupIDEQ(groupID)).Only(ctx)
	if err != nil {
		return nil, Secret{}, errors.New("凭据不存在")
	}
	ok, err := s.DB.Asset.Query().Where(asset.IDEQ(c.AssetID), asset.GroupIDEQ(groupID)).Exist(ctx)
	if err != nil || !ok {
		return nil, Secret{}, errors.New("资产已移组或删除，原凭据不可用")
	}
	secret, err := s.Vault.Open(c.Sealed, binding(c))
	return c, secret, err
}
