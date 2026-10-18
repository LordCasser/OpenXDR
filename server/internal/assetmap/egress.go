package assetmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/assetlink"
)

// EgressNotesOf 资产对公网外联的调查结论，键为公网地址。结构与服务说明相同：Name 是用途
func EgressNotesOf(a *ent.Asset) map[string]ServiceNote {
	notes := map[string]ServiceNote{}
	if len(a.EgressNotes) > 0 {
		_ = json.Unmarshal(a.EgressNotes, &notes)
	}
	return notes
}

// SetEgressNote 写入或清除一条外联结论。只收这台主机最近确实连过的公网地址，免得把编出来的地址写进去；
// 优先级与服务说明相同，调查结论不覆盖人工
func SetEgressNote(ctx context.Context, db *ent.Client, assetID uuid.UUID, ip string, n ServiceNote) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !Public(addr) {
		return errors.New("只能记录公网地址")
	}
	ip = addr.String()
	seen, err := db.AssetLink.Query().Where(assetlink.SrcAssetIDEQ(assetID), assetlink.DstIPEQ(ip), assetlink.LastSeenGT(time.Now().Add(-linkTTL))).Exist(ctx)
	if err != nil {
		return err
	}
	if !seen {
		return errors.New("这台主机最近没有连过这个地址")
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := tx.Asset.Get(ctx, assetID)
	if err != nil {
		return err
	}
	notes := EgressNotesOf(a)
	if old, ok := notes[ip]; ok && sourceRank[old.Source] > sourceRank[n.Source] {
		return errLowerSource
	}
	if n.Name == "" {
		delete(notes, ip)
	} else {
		n.At = time.Now()
		notes[ip] = n
	}
	raw, _ := json.Marshal(notes)
	if err := tx.Asset.UpdateOneID(assetID).SetEgressNotes(raw).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
