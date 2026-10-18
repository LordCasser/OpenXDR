import { ArrowRight, Check, Copy } from "lucide-react";
import { motion } from "motion/react";
import { useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, EASE } from "./chapter";

const REPO = "https://github.com/yaklang/OpenXDR";
const quickstart = (comment: string) => `git clone ${REPO}.git && cd OpenXDR
docker compose up -d
# ${comment} http://localhost:5173`;

const COPY = {
  "zh-CN": {
    kicker: "日常",
    title: (
      <>
        每天早上，
        <br />
        <span className="text-neutral-500">报告已经写好。</span>
      </>
    ),
    body: "预设任务每天巡检全组：复查待办，登记新问题，写成一份报告。\n只有需要你拍板的，才会来打扰你。",
    demo: "示例",
    report: {
      title: "生产组 · 每日主机巡检",
      time: "10:00 · 自动运行",
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
    startTitle: "五分钟，跑起来。",
    consoleAt: "控制台",
    copy: "复制",
    copied: "已复制",
    github: "在 GitHub 查看",
    docs: "部署文档",
    motto: ["纳管即运维，", "纳管即安全。"],
    license: "Apache-2.0 开源",
  },
  en: {
    kicker: "Every day",
    title: (
      <>
        Every morning,
        <br />
        <span className="text-neutral-500">the report is already written.</span>
      </>
    ),
    body: "Preset tasks check every host in the group, every day: revisit open findings, log new ones, write it all up.\nOnly what needs your call comes to you.",
    demo: "Sample",
    report: {
      title: "prod · Daily host inspection",
      time: "10:00 · scheduled",
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
    startTitle: "Up and running in five minutes.",
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
          <ChapterHead index="05" kicker={t.kicker} title={t.title} body={t.body} />

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
