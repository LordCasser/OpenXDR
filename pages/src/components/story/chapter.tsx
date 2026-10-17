import { motion } from "motion/react";
import type { ReactNode } from "react";

export const EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

/** 叙事章节的标题区：序号 + 主题词 + 标题 + 说明。 */
export function ChapterHead({
  index,
  kicker,
  title,
  body,
  tone = "emerald",
}: {
  index: string;
  kicker: string;
  title: ReactNode;
  body: ReactNode;
  tone?: "emerald" | "rose" | "amber" | "sky";
}) {
  const color = {
    emerald: "text-emerald-300",
    rose: "text-rose-300",
    amber: "text-amber-300",
    sky: "text-sky-300",
  }[tone];
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.8, ease: EASE }}
      className="max-w-2xl"
    >
      <p className={`font-mono text-xs uppercase tracking-[0.22em] ${color}`}>
        {index} · {kicker}
      </p>
      <h2 className="mt-5 text-3xl font-medium leading-[1.08] tracking-[-0.03em] text-white sm:text-5xl">
        {title}
      </h2>
      <p className="mt-5 text-base leading-relaxed text-neutral-400 sm:text-lg">
        {body}
      </p>
    </motion.div>
  );
}

/** 控制台外框：模拟 OpenXDR 控制台的一块面板。 */
export function Console({
  title,
  badge,
  children,
  className = "",
}: {
  title: string;
  badge?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`overflow-hidden rounded-2xl border border-white/10 bg-neutral-900/70 shadow-[0_40px_120px_-40px_rgba(16,185,129,0.25)] backdrop-blur ${className}`}
    >
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="ml-2 truncate text-xs text-neutral-400">{title}</span>
        {badge && <span className="ml-auto shrink-0">{badge}</span>}
      </div>
      {children}
    </div>
  );
}

export function DemoBadge({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-neutral-500">
      {label}
    </span>
  );
}
