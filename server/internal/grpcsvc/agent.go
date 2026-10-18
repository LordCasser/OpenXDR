// Package grpcsvc 实现 agent 专属 gRPC 通道：注册 + 事件流上报。
package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/pb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	DB *ent.Client
	// SQL 核对平台指令标记用；不配置时不认指令标记，照常告警
	SQL         cmdorigin.Querier
	Rules       *sigma.Engine
	DedupWindow time.Duration
	Hub         *response.Hub
	Suppress    *suppress.Store
	Intel       *intel.Store
	Events      eventbus.Bus
	// agent 安装包与自动升级开关
	Dist        *enroll.Dist
	AutoUpgrade bool
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// 绑定证书只能注册自己的主机名，防止认领他人身份拿走 agent_id
	if host, bound := certHostname(ctx); bound && host != req.Hostname {
		return nil, status.Error(codes.PermissionDenied, "hostname 与证书绑定的主机不符")
	}
	a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(req.Hostname)).First(ctx)
	if ent.IsNotFound(err) {
		a, err = s.DB.Asset.Create().SetHostname(req.Hostname).Save(ctx)
	}
	if err != nil {
		return nil, err
	}

	agentID := uuid.Must(uuid.NewV7())
	if a.AgentID != nil {
		agentID = *a.AgentID
	}
	if err := a.Update().
		SetOs(req.Os).
		SetAgentID(agentID).
		SetIPAddrs(req.IpAddrs).
		SetAgentVersion(req.AgentVersion).
		SetLastSeen(time.Now()).
		Exec(ctx); err != nil {
		return nil, err
	}
	// 采集配置随注册下发：agent 断线重连会重新注册，改配置最迟一次重连后生效
	resp := &pb.RegisterResponse{
		AgentId:    agentID.String(),
		ConfigJson: string(a.Config),
	}
	// 自动升级：分发目录里的版本与 agent 自身不同就让它换。不报哈希的老 agent 不会升级，也不会被要求
	if platform := enroll.Platform(req.Os, req.Arch); s.AutoUpgrade && req.BinarySha256 != "" && platform != "" {
		if want := s.Dist.SHA256(platform); want != "" && want != req.BinarySha256 {
			resp.UpgradeSha256, resp.UpgradePlatform = want, platform
			slog.Info("下发 agent 升级", "host", req.Hostname, "from", req.AgentVersion, "platform", platform)
		}
	}
	return resp, nil
}

// downloadChunk 每块 256 KiB，远小于 gRPC 默认的 4 MiB 消息上限
const downloadChunk = 256 << 10

// DownloadAgent 分块推送安装包。哈希不符说明分发目录刚换了版本，拒绝后 agent 下次注册拿新哈希重来。
func (s *Server) DownloadAgent(req *pb.DownloadRequest, stream pb.AgentService_DownloadAgentServer) error {
	if want := s.Dist.SHA256(req.Platform); want == "" || want != req.Sha256 {
		return status.Error(codes.FailedPrecondition, "分发版本已变化或不存在")
	}
	f, err := s.Dist.Open(req.Platform)
	if err != nil {
		return status.Error(codes.NotFound, "安装包不存在")
	}
	defer f.Close()
	buf := make([]byte, downloadChunk)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if serr := stream.Send(&pb.AgentChunk{Data: buf[:n]}); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}
}

// 攒批落库的两个触发条件：满 batchSize 条，或距上次落库超过 flushInterval。
// 只按条数会让低流量的 agent 长时间不落库，事件在 server 内存里干等。
const (
	batchSize     = 500
	flushInterval = 2 * time.Second
)

func (s *Server) ReportEvents(stream pb.AgentService_ReportEventsServer) error {
	ctx := stream.Context()

	// stream.Recv 是阻塞调用，挪进 goroutine 才能和定时 flush 一起 select
	type recvResult struct {
		ev  *pb.AgentEvent
		err error
	}
	recvCh := make(chan recvResult)
	go func() {
		defer close(recvCh)
		for {
			ev, err := stream.Recv()
			select {
			case recvCh <- recvResult{ev, err}:
				if err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var received uint64
	var assetID *uuid.UUID
	var assetOS string
	var lastDropped uint64
	// 每个 agent_id 首次出现时核对证书身份，之后放行；假 id 直接断流
	verifiedIDs := map[string]bool{}
	var eventCreates []*ent.EventCreate
	var alertCreates []*ent.AlertCreate

	// 一条流对应一台主机，告警指纹 (rule_id, asset_id) 在流内就是 rule_id
	deduper := dedup.New(s.DedupWindow)

	flush := func() error {
		if len(eventCreates) > 0 {
			if _, err := s.DB.Event.CreateBulk(eventCreates...).Save(ctx); err != nil {
				return err
			}
			eventCreates = nil
		}
		if len(alertCreates) > 0 {
			if _, err := s.DB.Alert.CreateBulk(alertCreates...).Save(ctx); err != nil {
				return err
			}
			alertCreates = nil
		}
		return deduper.Flush(ctx, s.DB)
	}

	for {
		var ev *pb.AgentEvent
		select {
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
			continue
		case result, ok := <-recvCh:
			if !ok {
				return ctx.Err()
			}
			if errors.Is(result.err, io.EOF) {
				if err := flush(); err != nil {
					return err
				}
				return stream.SendAndClose(&pb.ReportAck{Received: received})
			}
			if result.err != nil {
				_ = flush() // 断流前尽力保住已收的
				return result.err
			}
			ev = result.ev
		}

		if !verifiedIDs[ev.AgentId] {
			id, err := uuid.Parse(ev.AgentId)
			if err != nil {
				return status.Error(codes.InvalidArgument, "agent_id 不是合法 UUID")
			}
			if err := s.verifyAgentID(ctx, id); err != nil {
				_ = flush() // 断流前保住此前已核验的事件
				return err
			}
			verifiedIDs[ev.AgentId] = true
		}

		// 累计值只在增长时报，避免每条事件刷屏
		if ev.DroppedEvents > lastDropped {
			slog.Warn("agent 采集队列溢出",
				"agent", ev.AgentId, "dropped", ev.DroppedEvents)
			lastDropped = ev.DroppedEvents
		}

		if assetID == nil {
			if agentGUID, err := uuid.Parse(ev.AgentId); err == nil {
				if a, err := s.DB.Asset.Query().Where(asset.AgentIDEQ(agentGUID)).First(ctx); err == nil {
					assetID = &a.ID
					if a.Os != nil {
						assetOS = strings.ToLower(*a.Os)
					}
				}
			}
		}

		raw := json.RawMessage(ev.RawJson)
		var rawMap map[string]any
		if json.Unmarshal(raw, &rawMap) != nil {
			raw = json.RawMessage("{}")
			rawMap = map[string]any{}
		}

		ts := time.Unix(0, ev.TsUnixNs)
		eventID := uuid.Must(uuid.NewV7())
		if s.Events != nil {
			partitionKey := ev.AgentId
			if assetID != nil {
				partitionKey = assetID.String()
			}
			var processGUID, parentGUID *uuid.UUID
			if id, parseErr := uuid.Parse(ev.ProcessGuid); parseErr == nil {
				processGUID = &id
			}
			if id, parseErr := uuid.Parse(ev.ParentProcessGuid); parseErr == nil {
				parentGUID = &id
			}
			fpSuffix := ""
			if ev.ClassUid == 1001 {
				if f, ok := rawMap["file"].(map[string]any); ok {
					if path, ok := f["path"].(string); ok {
						fpSuffix = "|" + path
					}
				}
			}
			eventID = ingest.StableID(ev.AgentId, strconv.FormatInt(ev.TsUnixNs, 10),
				strconv.FormatUint(uint64(ev.ClassUid), 10), ev.ProcessGuid, ev.ParentProcessGuid,
				ev.ConnTuple, string(raw))
			if err := s.Events.Publish(ctx, ingest.Envelope{
				Version: ingest.EnvelopeVersion, ID: eventID, PartitionKey: partitionKey,
				Timestamp: ts, ClassUID: int(ev.ClassUid), Source: "agent", AssetID: assetID,
				AssetOS: assetOS, ProcessGUID: processGUID, ParentProcessGUID: parentGUID,
				Username: ev.Username, ConnTuple: ev.ConnTuple, FingerprintSuffix: fpSuffix,
				Raw: sanitizeRawJSON(raw),
			}); err != nil {
				return status.Errorf(codes.Unavailable, "事件入队失败: %v", err)
			}
			received++
			continue
		}
		ec := s.DB.Event.Create().
			SetID(eventID).
			SetTs(ts).
			SetClassUID(int(ev.ClassUid)).
			SetSource("agent").
			SetNillableAssetID(assetID).
			SetRaw(sanitizeRawJSON(raw))
		if pg, err := uuid.Parse(ev.ProcessGuid); err == nil {
			ec.SetProcessGUID(pg)
		}
		if ppg, err := uuid.Parse(ev.ParentProcessGuid); err == nil {
			ec.SetParentProcessGUID(ppg)
		}
		if ev.Username != "" {
			ec.SetUsername(ev.Username)
		}
		if ev.ConnTuple != "" {
			ec.SetConnTuple(ev.ConnTuple)
		}
		eventCreates = append(eventCreates, ec)

		// 文件事件的实体键是路径：同一规则命中不同文件是不同的事，不能被合并；
		// 进程/网络事件保持粗指纹，那正是防告警风暴的设计
		fpSuffix := ""
		if ev.ClassUid == 1001 {
			if f, ok := rawMap["file"].(map[string]any); ok {
				if p, ok := f["path"].(string); ok {
					fpSuffix = "|" + p
				}
			}
		}

		sigma.WithActor(rawMap, ev.Username)
		hits := intel.Detections(s.Rules.Evaluate(int(ev.ClassUid), assetOS, rawMap), s.Intel.Match(rawMap, ts))
		var command *uuid.UUID
		if len(hits) > 0 {
			var err error
			if command, err = cmdorigin.Of(ctx, s.SQL, rawMap, assetID, ts); err != nil {
				return status.Errorf(codes.Unavailable, "核对平台指令失败: %v", err)
			}
		}
		for _, h := range hits {
			// 抑制先于去重：被压掉的命中不该占用去重槽位
			if s.Suppress.Suppressed(h.RuleID, assetID, rawMap, ts) {
				continue
			}
			fingerprint := h.RuleID + fpSuffix
			if command != nil {
				fingerprint += "|cmd:" + command.String()
			}
			if deduper.Hit(fingerprint, ts) {
				continue
			}
			alertID := uuid.Must(uuid.NewV7())
			alertCreates = append(alertCreates, s.DB.Alert.Create().
				SetID(alertID).
				SetTs(ts).
				SetRuleID(h.RuleID).
				SetSeverity(h.Severity).
				SetEventID(eventID).
				SetNillableAssetID(assetID).
				SetNillableCommandID(command).
				SetLastTs(ts))
			deduper.Track(fingerprint, alertID, ts)
		}

		// 爆破得手跨事件升级：成功登录前的窗口内同用户多次失败。
		// 先 flush 让同批未落库的失败事件可见，再回查——成功登录稀少，不构成负担
		if int(ev.ClassUid) == classAuth && authStatus(rawMap) == authStatusSuccess &&
			assetID != nil && ev.Username != "" {
			if err := flush(); err != nil {
				return err
			}
			if s.countAuthFailures(ctx, *assetID, ev.Username, ts) >= bruteforceThreshold &&
				!s.Suppress.Suppressed(sigma.RuleBruteforceSuccess, assetID, rawMap, ts) {
				fingerprint := sigma.RuleBruteforceSuccess + "|" + ev.Username
				if !deduper.Hit(fingerprint, ts) {
					alertID := uuid.Must(uuid.NewV7())
					alertCreates = append(alertCreates, s.DB.Alert.Create().
						SetID(alertID).
						SetTs(ts).
						SetRuleID(sigma.RuleBruteforceSuccess).
						SetSeverity(5).
						SetEventID(eventID).
						SetAssetID(*assetID).
						SetLastTs(ts))
					deduper.Track(fingerprint, alertID, ts)
				}
			}
		}

		// 长连接流，攒批落库
		if received++; received%batchSize == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}
