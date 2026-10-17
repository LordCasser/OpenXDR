import { ArrowRight, Check, Copy, Cpu, Filter, Network, ScrollText, ShieldCheck, Zap } from "lucide-react";
import { motion } from "motion/react";
import { useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, EASE } from "./chapter";

const REPO = "https://github.com/yaklang/OpenXDR";
const quickstart = (comment: string) => `git clone ${REPO}.git && cd OpenXDR
docker compose up -d
# ${comment} http://localhost:5173`;

const ICONS = [Cpu, ShieldCheck, Filter, Zap, ScrollText, Network];

const COPY = {
  "zh-CN": {
    kicker: "闭环",
    title: (
      <>
        每天清晨，
        <br />
        <span className="text-neutral-500">报告已经在等你。</span>
      </>
    ),
    body: "预设任务按 cron 巡检全组主机：复查遗留待办、登记新问题、交一份报告。需要人拍板的，才推送给你。",
    demo: "示例",
    report: {
      title: "生产组 · 每日主机巡检",
      time: "02:00 · 自动运行",
      stats: [
        ["3", "主机"],
        ["2", "已处理"],
        ["1", "待办"],
        ["0", "待复核事件"],
      ],
      lines: [
        [true, "web-01 磁盘 93% → 68%，journal 已清理"],
        [true, "db-01 可疑 sudo 账户已删除（经批准）"],
        [false, "gw-01 证书 21 天后到期，已登记待办"],
        [true, "三台主机时间同步、监听端口无异常"],
      ],
    },
    capsTitle: "装上之后你得到的",
    caps: [
      ["采集不挑环境", "eBPF / ETW 可选，不可用时自动降级到 netlink、fanotify、轮询，宁弱勿假"],
      ["检测有据可查", "Sigma 兼容规则、ATT&CK 矩阵、公开情报订阅，CI 用真实攻击语料守住检测能力"],
      ["层层降噪", "去重、可撤销抑制、实体关联、UEBA 首次出现、AI 带工具研判"],
      ["处置一键到位", "结束进程、隔离主机，全局开关与隔离放行清单兜底"],
      ["人始终拍板", "高风险命令阻塞审批，登录、审批、处置全部落审计"],
      ["能上生产", "mTLS 主机绑定证书、JetStream 分片队列、Patroni + VIP 高可用"],
    ],
    startTitle: "五分钟跑起来",
    consoleAt: "控制台",
    copy: "复制",
    copied: "已复制",
    github: "在 GitHub 查看",
    docs: "部署文档",
    motto: ["纳管即运维，", "纳管即安全。"],
    license: "Apache-2.0 开源",
  },
  en: {
    kicker: "Closing the loop",
    title: (
      <>
        Every morning,
        <br />
        <span className="text-neutral-500">the report is already waiting.</span>
      </>
    ),
    body: "Preset tasks inspect every host in the group on a cron schedule: re-check open findings, log new ones, file a report. Only what needs a human gets pushed to you.",
    demo: "Sample",
    report: {
      title: "prod · Daily host inspection",
      time: "02:00 · scheduled",
      stats: [
        ["3", "hosts"],
        ["2", "handled"],
        ["1", "open"],
        ["0", "to review"],
      ],
      lines: [
        [true, "web-01 disk 93% → 68%, journals trimmed"],
        [true, "db-01 suspicious sudo account removed (approved)"],
        [false, "gw-01 certificate expires in 21 days, finding logged"],
        [true, "Time sync and listening ports normal on all hosts"],
      ],
    },
    capsTitle: "What you get once it's installed",
    caps: [
      ["Collection that adapts", "eBPF / ETW optional, falls back to netlink, fanotify or polling — weaker beats fake"],
      ["Detection you can verify", "Sigma rules, ATT&CK matrix, public intel feeds; CI replays real attack commands"],
      ["Layered noise reduction", "Dedup, revocable suppression, entity correlation, UEBA first-seen, tool-using AI triage"],
      ["One-click response", "Kill processes, isolate hosts — guarded by a global switch and an isolation allowlist"],
      ["Humans stay in charge", "High-risk commands block for approval; logins, approvals and responses are audited"],
      ["Production-ready", "mTLS host-bound certs, sharded JetStream queues, Patroni + VIP high availability"],
    ],
    startTitle: "Up in five minutes",
    consoleAt: "console at",
    copy: "Copy",
    copied: "Copied",
    github: "View on GitHub",
    docs: "Deployment guide",
    motto: ["Onboarded means operated,", "onboarded means secured."],
    license: "Open source · Apache-2.0",
  },
};

export function Closing() {
  const t = useCopy(COPY);
  const [copied, setCopied] = useState(false);
  const commands = quickstart(t.consoleAt);
  const copy = async () => {
    await navigator.clipboard.writeText(commands);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <section id="start" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1400px]">
        <div className="grid gap-14 lg:grid-cols-2 lg:items-center">
          <ChapterHead index="04" kicker={t.kicker} title={t.title} body={t.body} />

          <motion.article
            initial={{ opacity: 0, y: 30, rotate: 1.5 }}
            whileInView={{ opacity: 1, y: 0, rotate: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.9, ease: EASE }}
            className="rounded-2xl border border-white/10 bg-neutral-100 p-6 text-neutral-900 shadow-[0_40px_120px_-30px_rgba(255,255,255,0.15)] sm:p-8"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-lg font-semibold tracking-tight">{t.report.title}</h3>
                <p className="mt-1 text-xs text-neutral-500">{t.report.time}</p>
              </div>
              <span className="rounded-full border border-neutral-300 px-2 py-0.5 text-[10px] uppercase tracking-wider text-neutral-500">
                {t.demo}
              </span>
            </div>
            <dl className="mt-6 grid grid-cols-4 gap-2 border-y border-neutral-300 py-4">
              {t.report.stats.map(([n, label]) => (
                <div key={label}>
                  <dt className="sr-only">{label}</dt>
                  <dd className="text-2xl font-semibold tabular-nums">{n}</dd>
                  <dd className="text-xs text-neutral-500">{label}</dd>
                </div>
              ))}
            </dl>
            <ul className="mt-5 space-y-2.5 text-sm">
              {t.report.lines.map(([ok, text], i) => (
                <motion.li
                  key={String(text)}
                  initial={{ opacity: 0, x: -8 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.4 + i * 0.12, duration: 0.5 }}
                  className="flex gap-2.5"
                >
                  <span
                    className={`mt-1 h-2 w-2 shrink-0 rounded-full ${ok ? "bg-emerald-500" : "bg-amber-500"}`}
                  />
                  {text}
                </motion.li>
              ))}
            </ul>
          </motion.article>
        </div>

        <h3 className="mt-32 text-sm uppercase tracking-[0.2em] text-neutral-500">{t.capsTitle}</h3>
        <div className="mt-6 grid gap-px overflow-hidden rounded-2xl border border-white/10 bg-white/10 sm:grid-cols-2 lg:grid-cols-3">
          {t.caps.map(([title, desc], i) => {
            const Icon = ICONS[i];
            return (
              <motion.div
                key={title}
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.06, duration: 0.6 }}
                className="bg-neutral-950 p-6 transition-colors hover:bg-neutral-900"
              >
                <Icon className="h-5 w-5 text-emerald-300" />
                <p className="mt-4 font-medium text-white">{title}</p>
                <p className="mt-2 text-sm leading-relaxed text-neutral-400">{desc}</p>
              </motion.div>
            );
          })}
        </div>

        <div className="mt-32 grid gap-10 lg:grid-cols-2 lg:items-end">
          <div>
            <p className="text-4xl font-medium leading-[1.1] tracking-[-0.03em] text-white sm:text-6xl">
              {t.motto[0]}
              <br />
              <span className="text-emerald-300">{t.motto[1]}</span>
            </p>
            <div className="mt-10 flex flex-col gap-3 sm:flex-row">
              <a
                href={REPO}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center justify-center rounded-full bg-white px-7 py-3 text-sm font-medium text-neutral-950 transition-colors hover:bg-neutral-200"
              >
                {t.github}
                <ArrowRight className="ml-2 h-4 w-4" />
              </a>
              <a
                href={`${REPO}/blob/master/docs/deployment.md`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center justify-center rounded-full border border-white/20 px-7 py-3 text-sm font-medium text-white transition-colors hover:bg-white/10"
              >
                {t.docs}
              </a>
            </div>
            <p className="mt-6 text-xs text-neutral-500">{t.license}</p>
          </div>

          <div className="overflow-hidden rounded-2xl border border-white/10 bg-black/60">
            <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
              <span className="text-xs text-neutral-400">{t.startTitle}</span>
              <button
                type="button"
                onClick={copy}
                className="inline-flex items-center gap-1.5 text-xs text-neutral-400 transition-colors hover:text-white"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? t.copied : t.copy}
              </button>
            </div>
            <pre className="overflow-x-auto p-5 font-mono text-sm leading-7 text-neutral-300">
              {commands.split("\n").map((line) => (
                <div key={line} className={line.startsWith("#") ? "text-neutral-600" : ""}>
                  {!line.startsWith("#") && <span className="select-none text-emerald-400">$ </span>}
                  {line}
                </div>
              ))}
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}
