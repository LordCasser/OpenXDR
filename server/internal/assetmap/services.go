package assetmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// ServiceNote 一个监听服务的说明：端口表认不出时靠它命名，调查结论与人工判断也记在这里
type ServiceNote struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
	// Risk 覆盖按端口推测的风险档；空表示沿用端口推测
	Risk   string    `json:"risk,omitempty"`
	Source string    `json:"source"` // ai 标注时识别 / investigation AI 调查 / human 人工
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
}

// 来源的优先级：高的不被低的覆盖。AI 自动识别只覆盖自己写的，调查结论不覆盖人工
var sourceRank = map[string]int{"ai": 1, "investigation": 2, "human": 3}

func serviceKey(proto string, port int) string { return proto + "/" + strconv.Itoa(port) }

// NotesOf 资产上的全部服务说明，键为 协议/端口
func NotesOf(a *ent.Asset) map[string]ServiceNote {
	notes := map[string]ServiceNote{}
	if len(a.ServiceNotes) > 0 {
		_ = json.Unmarshal(a.ServiceNotes, &notes)
	}
	return notes
}

// listens 资产上有没有这个监听，没有的不收说明
func listens(a *ent.Asset, key string) bool {
	return slices.ContainsFunc(listenersOf(a), func(l Listener) bool { return serviceKey(l.Proto, l.Port) == key })
}

var errLowerSource = errors.New("该服务已有更高优先级的结论（调查或人工），不覆盖")

// SetServiceNote 写入或清除一条说明。name 为空表示清除；清除也要遵守优先级。
// 返回 errLowerSource 时说明被更可信的结论挡住了，调用方原样转告即可
func SetServiceNote(ctx context.Context, db *ent.Client, assetID uuid.UUID, key string, n ServiceNote) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := tx.Asset.Get(ctx, assetID)
	if err != nil {
		return err
	}
	if !listens(a, key) {
		return fmt.Errorf("资产上没有监听 %s", key)
	}
	notes := NotesOf(a)
	if old, ok := notes[key]; ok && sourceRank[old.Source] > sourceRank[n.Source] {
		return errLowerSource
	}
	if n.Name == "" {
		delete(notes, key)
	} else {
		n.At = time.Now()
		notes[key] = n
	}
	raw, _ := json.Marshal(notes)
	if err := tx.Asset.UpdateOneID(assetID).SetServiceNotes(raw).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

// IsLowerSource 是否因优先级被挡住
func IsLowerSource(err error) bool { return errors.Is(err, errLowerSource) }

// CleanNote 校验并截断说明字段；风险只接受 high / medium / low 或空
func CleanNote(name, note, risk string) (ServiceNote, error) {
	n := ServiceNote{Name: clean(name, 32), Note: clean(note, 300), Risk: risk}
	if n.Risk != "" && !slices.Contains([]string{"high", "medium", "low"}, n.Risk) {
		return n, errors.New("risk 只能是 high / medium / low")
	}
	return n, nil
}
