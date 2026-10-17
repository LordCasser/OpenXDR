import { Bot, CheckCircle2, FileText, Hand, ListTodo, Play, RotateCcw, Terminal } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE } from "./chapter";

type Item =
  | { kind: "user" | "ai"; text: string }
  | { kind: "exec"; host: string; cmd: string; out: string }
  | { kind: "gate"; host: string; cmd: string }
  | { kind: "track"; done: boolean; text: string }
  | { kind: "report"; text: string };

type Decision = "approve" | "reject";

const COPY = {
  "zh-CN": {
    kicker: "纳管即运维",
    title: (
      <>
        说一句话，
        <br />
        <span className="text-neutral-500">它去主机上动手。</span>
      </>
    ),
    body: "AI 助手能在组内主机上执行命令、按组只读查库、登记待办、交报告。危险的那一步，停下来等你。",
    points: [
      "名单外的命令直接执行，不用每条都点批准",
      "命中高风险名单的命令阻塞等组管理员批准，同时推送通知。它不是被拒绝，所以 AI 也没有理由绕路",
      "对话在服务端后台运行，切页、关浏览器都不中断。事件与待办可多选「交给 AI」接着处理",
    ],
    hint: "试试点「拒绝」，看它怎么收场。",
    console: "AI 助手 · 生产组",
    demo: "演示",
    send: "巡检一下生产组：磁盘、异常服务、可疑账户，能修的直接修。",
    sendLabel: "发送",
    gate: "命中高风险名单，已暂停，等待组管理员批准（已通知）",
    approve: "批准",
    reject: "拒绝",
    approved: "已批准 · 你",
    rejected: "已拒绝 · 你",
    open: "待办",
    resolved: "已解决",
    replay: "重播",
    main: [
      { kind: "exec", host: "web-01", cmd: "df -h / | tail -1", out: "/dev/sda1   40G   37G  2.9G  93% /" },
      { kind: "exec", host: "web-01", cmd: "du -sh /var/log/journal", out: "11G\t/var/log/journal" },
      { kind: "exec", host: "web-01", cmd: "journalctl --vacuum-size=500M", out: "Vacuuming done, freed 10.4G of archived journals." },
      { kind: "ai", text: "web-01 根分区 93%，是 journal 日志堆积。已清理到 500M，现在 68%。" },
      { kind: "exec", host: "db-01", cmd: "getent group wheel", out: "wheel:x:10:ops,tmpadmin" },
      { kind: "exec", host: "db-01", cmd: "last -n 1 tmpadmin", out: "tmpadmin pts/0  203.0.113.7  Mon Oct 12 03:14 - 03:41" },
      { kind: "ai", text: "db-01 的 tmpadmin 在 wheel 组，凌晨 3 点从外网登录过，与事件「新增 sudo 账户」对得上。建议删除。" },
      { kind: "gate", host: "db-01", cmd: "userdel -r tmpadmin" },
    ],
    approveTail: [
      { kind: "ai", text: "已删除 tmpadmin，待办标为已解决。事件结案仍由你来拍板。" },
      { kind: "track", done: true, text: "db-01 可疑 sudo 账户 tmpadmin 已删除" },
      { kind: "report", text: "生产组巡检报告 · 2 项已处理 · 0 项待办" },
    ],
    rejectTail: [
      { kind: "ai", text: "好，不删。先保留账户，登记成待办，请确认它是不是合法的运维账号。" },
      { kind: "track", done: false, text: "db-01 可疑 sudo 账户 tmpadmin 待确认" },
      { kind: "report", text: "生产组巡检报告 · 1 项已处理 · 1 项待办" },
    ],
  },
  en: {
    kicker: "Onboarded means operated",
    title: (
      <>
        Say it once,
        <br />
        <span className="text-neutral-500">it does the work on the hosts.</span>
      </>
    ),
    body: "The AI assistant runs commands on the group's hosts, queries data through a read-only view, tracks findings and files reports. At the dangerous step, it stops and waits for you.",
    points: [
      "Commands outside the list run directly — no clicking approve on every line",
      "Commands on the high-risk list block until a group admin approves, with a notification. They aren't denied, so the AI has no reason to look for a way around",
      "Conversations run in the background on the server. Switch pages or close the browser — nothing stops. Multi-select incidents and findings and hand them to the AI",
    ],
    hint: "Try clicking “Reject” and see how it wraps up.",
    console: "AI assistant · prod",
    demo: "Demo",
    send: "Inspect the prod group: disks, failing services, suspicious accounts. Fix what you can.",
    sendLabel: "Send",
    gate: "On the high-risk list — paused, waiting for a group admin (notified)",
    approve: "Approve",
    reject: "Reject",
    approved: "Approved · you",
    rejected: "Rejected · you",
    open: "Open",
    resolved: "Resolved",
    replay: "Replay",
    main: [
      { kind: "exec", host: "web-01", cmd: "df -h / | tail -1", out: "/dev/sda1   40G   37G  2.9G  93% /" },
      { kind: "exec", host: "web-01", cmd: "du -sh /var/log/journal", out: "11G\t/var/log/journal" },
      { kind: "exec", host: "web-01", cmd: "journalctl --vacuum-size=500M", out: "Vacuuming done, freed 10.4G of archived journals." },
      { kind: "ai", text: "web-01 root was at 93% from journal buildup. Trimmed to 500M, now at 68%." },
      { kind: "exec", host: "db-01", cmd: "getent group wheel", out: "wheel:x:10:ops,tmpadmin" },
      { kind: "exec", host: "db-01", cmd: "last -n 1 tmpadmin", out: "tmpadmin pts/0  203.0.113.7  Mon Oct 12 03:14 - 03:41" },
      { kind: "ai", text: "tmpadmin on db-01 is in wheel and logged in from outside at 3 a.m. — it matches the “new sudo account” incident. I suggest removing it." },
      { kind: "gate", host: "db-01", cmd: "userdel -r tmpadmin" },
    ],
    approveTail: [
      { kind: "ai", text: "tmpadmin removed and the finding marked resolved. Closing the incident is still your call." },
      { kind: "track", done: true, text: "Suspicious sudo account tmpadmin on db-01 removed" },
      { kind: "report", text: "prod inspection report · 2 handled · 0 open" },
    ],
    rejectTail: [
      { kind: "ai", text: "Understood, keeping it. Logged a finding so someone confirms whether it's a legitimate ops account." },
      { kind: "track", done: false, text: "Suspicious sudo account tmpadmin on db-01 to confirm" },
      { kind: "report", text: "prod inspection report · 1 handled · 1 open" },
    ],
  },
} satisfies Record<string, { main: Item[]; approveTail: Item[]; rejectTail: Item[] } & Record<string, unknown>>;

type Copy = (typeof COPY)["en"];

export function Assistant() {
  const t = useCopy(COPY) as Copy;
  const [step, setStep] = useState(-1);
  const [decision, setDecision] = useState<Decision>();
  const list = useRef<HTMLDivElement>(null);

  const tail: Item[] = decision === "approve" ? t.approveTail : decision === "reject" ? t.rejectTail : [];
  const script: Item[] = [{ kind: "user", text: t.send }, ...t.main, ...tail];
  const shown = step < 0 ? [] : script.slice(0, step + 1);
  const waiting = shown.at(-1)?.kind === "gate" && !decision;
  const finished = step >= 0 && step >= script.length - 1 && !!decision;

  useEffect(() => {
    if (step < 0 || waiting || step >= script.length - 1) return;
    const timer = setTimeout(() => setStep((n) => n + 1), script[step + 1].kind === "exec" ? 900 : 1300);
    return () => clearTimeout(timer);
  }, [step, waiting, script.length]);

  // 只滚动对话框自身，不带动整页
  useEffect(() => {
    list.current?.scrollTo({ top: list.current.scrollHeight, behavior: "smooth" });
  }, [step, decision]);

  const reset = () => {
    setStep(-1);
    setDecision(undefined);
  };

  return (
    <section id="operate" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="03" kicker={t.kicker} title={t.title} body={t.body} tone="sky" />
          <ul className="mt-10 space-y-4">
            {t.points.map((p) => (
              <li key={p} className="flex gap-3 text-sm leading-relaxed text-neutral-400">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
                {p}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
            <div ref={list} className="h-[480px] space-y-3 overflow-y-auto p-5" aria-live="polite">
              {shown.map((item, i) => (
                <motion.div
                  key={`${i}-${item.kind}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.45, ease: EASE }}
                >
                  <Row item={item} decision={decision} decide={setDecision} t={t} />
                </motion.div>
              ))}
              {step >= 0 && !waiting && !finished && (
                <div className="flex items-center gap-1.5 pl-1 text-neutral-500">
                  {[0, 1, 2].map((d) => (
                    <motion.span
                      key={d}
                      className="h-1.5 w-1.5 rounded-full bg-neutral-500"
                      animate={{ opacity: [0.2, 1, 0.2] }}
                      transition={{ duration: 1, repeat: Infinity, delay: d * 0.2 }}
                    />
                  ))}
                </div>
              )}
            </div>
            <div className="border-t border-white/10 p-4">
              {step < 0 ? (
                <button
                  type="button"
                  onClick={() => setStep(0)}
                  className="flex w-full items-center gap-3 rounded-xl border border-sky-300/30 bg-sky-400/[0.07] px-4 py-3 text-left text-sm text-sky-50 transition-colors hover:bg-sky-400/[0.14]"
                >
                  <span className="flex-1">{t.send}</span>
                  <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-sky-300 px-3 py-1 text-xs font-medium text-neutral-950">
                    <Play className="h-3 w-3" />
                    {t.sendLabel}
                  </span>
                </button>
              ) : (
                <div className="flex items-center justify-between gap-4 text-xs text-neutral-500">
                  <span>{waiting ? t.hint : ""}</span>
                  {finished && (
                    <button
                      type="button"
                      onClick={reset}
                      className="inline-flex items-center gap-1.5 rounded-full border border-white/15 px-3 py-1.5 text-sm text-white hover:bg-white/10"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      {t.replay}
                    </button>
                  )}
                </div>
              )}
            </div>
          </Console>
        </div>
      </div>
    </section>
  );
}

function Row({
  item,
  decision,
  decide,
  t,
}: {
  item: Item;
  decision?: Decision;
  decide: (d: Decision) => void;
  t: Copy;
}) {
  switch (item.kind) {
    case "user":
      return (
        <div className="ml-auto max-w-[85%] rounded-2xl rounded-br-md bg-sky-400/15 px-4 py-2.5 text-sm text-sky-50">
          {item.text}
        </div>
      );
    case "ai":
      return (
        <div className="flex max-w-[90%] gap-2.5 text-sm leading-relaxed text-neutral-200">
          <Bot className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
          <p>{item.text}</p>
        </div>
      );
    case "exec":
      return (
        <div className="rounded-lg border border-white/10 bg-black/40 font-mono text-xs">
          <div className="flex items-center gap-2 px-3 py-2 text-neutral-300">
            <Terminal className="h-3.5 w-3.5 text-neutral-500" />
            <span className="text-neutral-500">{item.host}</span>
            <span className="truncate">$ {item.cmd}</span>
          </div>
          <motion.pre
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.45 }}
            className="overflow-x-auto border-t border-white/5 px-3 py-2 text-neutral-500"
          >
            {item.out}
          </motion.pre>
        </div>
      );
    case "gate":
      return (
        <div
          className={`rounded-lg border font-mono text-xs ${
            decision === "reject" ? "border-white/10 bg-white/[0.02]" : "border-amber-300/40 bg-amber-400/[0.07]"
          }`}
        >
          <div className="flex items-center gap-2 px-3 py-2 text-neutral-200">
            <Hand className="h-3.5 w-3.5 text-amber-300" />
            <span className="text-neutral-500">{item.host}</span>
            <span className="truncate">$ {item.cmd}</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 border-t border-white/5 px-3 py-2.5 font-sans">
            {decision ? (
              <span className={decision === "approve" ? "text-emerald-300" : "text-neutral-400"}>
                {decision === "approve" ? t.approved : t.rejected}
                {decision === "approve" && <span className="ml-3 font-mono text-neutral-500">exit 0</span>}
              </span>
            ) : (
              <>
                <span className="flex-1 text-amber-200">{t.gate}</span>
                <button
                  type="button"
                  onClick={() => decide("approve")}
                  className="rounded-full bg-amber-300 px-3.5 py-1 text-xs font-medium text-neutral-950 hover:bg-amber-200"
                >
                  {t.approve}
                </button>
                <button
                  type="button"
                  onClick={() => decide("reject")}
                  className="rounded-full border border-white/20 px-3.5 py-1 text-xs text-white hover:bg-white/10"
                >
                  {t.reject}
                </button>
              </>
            )}
          </div>
        </div>
      );
    case "track":
      return (
        <div className="flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-neutral-300">
          <ListTodo className="h-3.5 w-3.5 text-neutral-500" />
          <span
            className={`rounded px-1.5 py-0.5 ${item.done ? "bg-emerald-400/15 text-emerald-300" : "bg-amber-400/15 text-amber-300"}`}
          >
            {item.done ? t.resolved : t.open}
          </span>
          {item.text}
        </div>
      );
    case "report":
      return (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-400/25 bg-emerald-400/[0.06] px-3 py-2.5 text-sm text-emerald-100">
          <FileText className="h-4 w-4 text-emerald-300" />
          {item.text}
          <span className="ml-auto text-xs text-emerald-300/70">HTML · PDF</span>
        </div>
      );
  }
}
