// 品牌标：盾形底 + 交叉的 X，寓意端（Endpoint）、网（Network）、日志汇聚到一处
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-label="OpenXDR">
      <defs>
        <linearGradient id="oxdr-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#4096ff" />
          <stop offset="1" stopColor="#1668dc" />
        </linearGradient>
      </defs>
      <path d="M16 2 L28 6.5 V15.5 C28 22.8 22.9 28.2 16 30 C9.1 28.2 4 22.8 4 15.5 V6.5 Z" fill="url(#oxdr-g)" />
      <path d="M11 10.5 L21 21.5 M21 10.5 L11 21.5" stroke="#fff" strokeWidth="2.8" strokeLinecap="round" />
      <circle cx="16" cy="16" r="2.4" fill="#fff" />
    </svg>
  )
}
