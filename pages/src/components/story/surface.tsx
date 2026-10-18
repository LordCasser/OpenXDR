import { CheckCircle2, Globe, HelpCircle } from "lucide-react";
import { motion } from "motion/react";
import { useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE } from "./chapter";

// 示意数据：风险分 = 暴露级别 × 端口风险 × 重要程度，与 server/internal/assetmap 同一口径
type Service = { port: string; name: string; exposure: number; port_risk: number; public?: boolean };
type Asset = { host: string; role: string; weight: number; services: Service[] };

const ZONES: { key: "external" | "dmz" | "internal"; assets: Asset[]; blind?: string }[] = [
  {
    key: "external",
    assets: [
      {
        host: "gw-01",
        role: "gateway",
        weight: 5,
        services: [
          { port: "22/tcp", name: "SSH", exposure: 20, port_risk: 3, public: true },
          { port: "443/tcp", name: "HTTPS", exposure: 20, port_risk: 1, public: true },
        ],
      },
    ],
  },
  {
    key: "dmz",
    assets: [
      { host: "web-01", role: "web", weight: 4, services: [{ port: "8080/tcp", name: "HTTP", exposure: 6, port_risk: 2 }] },
    ],
  },
  {
    key: "internal",
    assets: [
      { host: "db-01", role: "db", weight: 5, services: [{ port: "5432/tcp", name: "PostgreSQL", exposure: 2, port_risk: 3 }] },
    ],
    blind: "10.0.1.77",
  },
];

const COPY = {
  "zh-CN": {
    kicker: "看清",
    title: (
      <>
        每一个入口，
        <br />
        <span className="text-neutral-500">都在明处。</span>
      </>
    ),
    body: "agent 上报监听端口与云环境，连接关系自动汇成依赖图。\n哪些服务暴露在外、谁在访问、哪里还是盲区，一目了然。",
    points: [
      "每台机器做什么、有多重要，AI 先标好。你可以改，也可以锁定",
      "风险分按规则计算：暴露 × 端口风险 × 重要程度，不经过模型",
      "连过却没接入的机器，列为盲区",
    ],
    console: "资产 · 攻击面",
    demo: "演示",
    internet: "互联网",
    zones: { external: "公网区", dmz: "隔离区", internal: "内网" },
    roles: { gateway: "网关", web: "Web 服务", db: "数据库" } as Record<string, string>,
    weight: "重要",
    publicHit: "有公网访问",
    blind: "盲区 · 未接入",
    hint: "点一行服务，看它的分是怎么算的",
    exposure: "暴露",
    portRisk: "端口风险",
    score: "风险分",
    sources: "来源：14 个公网地址，近 24 小时 2,310 次连接",
    sourcesNone: "来源：只有内网主机访问过",
  },
  en: {
    kicker: "See",
    title: (
      <>
        Every way in,
        <br />
        <span className="text-neutral-500">in plain sight.</span>
      </>
    ),
    body: "Agents report listening ports and cloud context; connections become a dependency map.\nWhat's exposed, who's knocking, where the blind spots are — at a glance.",
    points: [
      "What each machine does and how much it matters — labeled by AI, editable and lockable by you",
      "Risk is computed by rule: exposure × port risk × importance. No model involved",
      "Machines seen on the wire but never onboarded show up as blind spots",
    ],
    console: "Assets · Attack surface",
    demo: "Demo",
    internet: "Internet",
    zones: { external: "Public", dmz: "DMZ", internal: "Internal" },
    roles: { gateway: "Gateway", web: "Web", db: "Database" } as Record<string, string>,
    weight: "weight",
    publicHit: "Public access",
    blind: "Blind spot · not onboarded",
    hint: "Click a service to see how its score adds up",
    exposure: "Exposure",
    portRisk: "Port risk",
    score: "Risk",
    sources: "Sources: 14 public addresses, 2,310 connections in 24 h",
    sourcesNone: "Sources: internal hosts only",
  },
};

const score = (a: Asset, s: Service) => s.exposure * s.port_risk * a.weight;

export function Surface() {
  const t = useCopy(COPY);
  const [picked, setPicked] = useState("gw-01 22/tcp");
  const all = ZONES.flatMap((z) => z.assets.flatMap((a) => a.services.map((s) => ({ a, s }))));
  const sel = all.find(({ a, s }) => `${a.host} ${s.port}` === picked) ?? all[0];

  return (
    <section id="surface" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="04" kicker={t.kicker} title={t.title} body={t.body} tone="amber" />
          <ul className="mt-10 space-y-4">
            {t.points.map((p) => (
              <li key={p} className="flex gap-3 text-sm leading-relaxed text-neutral-400">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                {p}
              </li>
            ))}
          </ul>
        </div>

        <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
          <div className="grid gap-3 p-5 sm:grid-cols-[auto_repeat(3,minmax(0,1fr))]">
            <div className="flex items-center gap-2 text-xs text-neutral-400 sm:flex-col sm:justify-center sm:px-2">
              <Globe className="h-5 w-5 text-amber-300" />
              {t.internet}
            </div>
            {ZONES.map((zone, zi) => (
              <motion.div
                key={zone.key}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, ease: EASE, delay: zi * 0.1 }}
                className="rounded-xl border border-white/10 bg-white/[0.02] p-3"
              >
                <p className="mb-3 text-[11px] uppercase tracking-wider text-neutral-500">{t.zones[zone.key]}</p>
                <div className="space-y-3">
                  {zone.assets.map((a) => (
                    <div key={a.host} className="rounded-lg border border-white/10 bg-neutral-950/80">
                      <div className="flex items-baseline justify-between gap-2 border-b border-white/5 px-3 py-2">
                        <span className="font-mono text-xs text-white">{a.host}</span>
                        <span className="text-[10px] text-neutral-500">
                          {t.roles[a.role]} · {t.weight} {a.weight}
                        </span>
                      </div>
                      {a.services.map((s) => {
                        const id = `${a.host} ${s.port}`;
                        const on = id === picked;
                        return (
                          <button
                            key={s.port}
                            type="button"
                            onClick={() => setPicked(id)}
                            aria-pressed={on}
                            className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition-colors ${
                              on ? "bg-amber-400/10 text-amber-100" : "text-neutral-400 hover:bg-white/5"
                            }`}
                          >
                            <span className="font-mono">{s.port}</span>
                            <span className="truncate">{s.name}</span>
                            {s.public && <Globe className="h-3 w-3 shrink-0 text-amber-300" aria-label={t.publicHit} />}
                            <span className="ml-auto font-mono tabular-nums">{score(a, s)}</span>
                          </button>
                        );
                      })}
                    </div>
                  ))}
                  {zone.blind && (
                    <div className="flex items-center gap-2 rounded-lg border border-dashed border-white/20 px-3 py-2 text-[11px] text-neutral-500">
                      <HelpCircle className="h-3.5 w-3.5 shrink-0" />
                      <span className="font-mono">{zone.blind}</span>
                      <span className="truncate">{t.blind}</span>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>

          <div className="border-t border-white/10 p-5" aria-live="polite">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="font-mono text-sm text-white">{picked}</span>
              <span className="text-xs text-neutral-500">{sel.s.name}</span>
              {sel.s.public && (
                <span className="rounded-full bg-amber-400/15 px-2 py-0.5 text-[10px] text-amber-200">{t.publicHit}</span>
              )}
            </div>
            <p className="mt-3 flex flex-wrap items-baseline gap-x-2 gap-y-1 font-mono text-sm text-neutral-400">
              <span>
                {t.exposure} <span className="text-white">{sel.s.exposure}</span>
              </span>
              ×
              <span>
                {t.portRisk} <span className="text-white">{sel.s.port_risk}</span>
              </span>
              ×
              <span>
                {t.weight} <span className="text-white">{sel.a.weight}</span>
              </span>
              =
              <span className="text-2xl font-medium text-amber-300">{score(sel.a, sel.s)}</span>
            </p>
            <p className="mt-2 text-xs text-neutral-500">{sel.s.public ? t.sources : t.sourcesNone}</p>
            <p className="mt-4 text-[11px] text-neutral-600">{t.hint}</p>
          </div>
        </Console>
      </div>
    </section>
  );
}
