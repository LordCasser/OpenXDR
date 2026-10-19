import { motion, type Transition } from 'motion/react'
import { useId } from 'react'

// 与 public/favicon.svg 同一组路径：盾牌、X、中心菱形。animate 为 false 时直接画成品（欢迎首屏用）
const SHIELD = 'M32 3 58 13v19c0 14-11 24-26 30C17 56 6 46 6 32V13L32 3Z'
const STROKE_A = 'm19 19 26 26'
const STROKE_B = 'm45 19-26 26'
const CORE = 'm32 25 7 7-7 7-7-7 7-7Z'

const EASE = [0.22, 1, 0.36, 1] as const

export function BrandMark({ size, animate = true, delay = 0 }: { size: number; animate?: boolean; delay?: number }) {
  const id = useId().replace(/:/g, '')
  const at = (t: number, d: number, extra?: Transition): Transition => ({ delay: delay + t, duration: d, ease: EASE, ...extra })
  const still = { initial: false as const }
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} fill="none" aria-hidden className="wl-mark">
      <defs>
        <linearGradient id={`${id}-fill`} x1="10" y1="4" x2="54" y2="60" gradientUnits="userSpaceOnUse">
          <stop stopColor="#5b9dff" />
          <stop offset="1" stopColor="#1250c4" />
        </linearGradient>
        <linearGradient id={`${id}-edge`} x1="6" y1="3" x2="58" y2="62" gradientUnits="userSpaceOnUse">
          <stop stopColor="#c7dcff" />
          <stop offset="1" stopColor="#4f8cff" />
        </linearGradient>
        <filter id={`${id}-glow`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.2" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      {/* 盾牌：先沿轮廓描边，再填色 */}
      <motion.path d={SHIELD} fill={`url(#${id}-fill)`}
        {...(animate ? { initial: { fillOpacity: 0 }, animate: { fillOpacity: 1 }, transition: at(1.1, 0.9) } : still)} />
      <motion.path d={SHIELD} stroke={`url(#${id}-edge)`} strokeWidth="1.6" strokeLinejoin="round" filter={`url(#${id}-glow)`}
        {...(animate
          ? { initial: { pathLength: 0, opacity: 0 }, animate: { pathLength: 1, opacity: [0, 1, 1, 0.35] }, transition: at(0, 1.5, { opacity: { delay, duration: 2.2, times: [0, 0.1, 0.7, 1] } }) }
          : { ...still, opacity: 0.35 })} />
      {/* X 两笔依次划过；长度为 0 时圆角端帽仍会画出一个点，开始前先透明 */}
      {[STROKE_A, STROKE_B].map((d, i) => (
        <motion.path key={d} d={d} stroke="#fff" strokeWidth="7" strokeLinecap="round"
          {...(animate ? { initial: { pathLength: 0, opacity: 0 }, animate: { pathLength: 1, opacity: 1 }, transition: at(1.35 + i * 0.22, 0.45, { opacity: { delay: delay + 1.35 + i * 0.22, duration: 0.01 } }) } : still)} />
      ))}
      {/* 中心菱形弹出 */}
      <motion.path d={CORE} fill="#a9d1ff" stroke="#1250c4" strokeWidth="3" style={{ transformOrigin: '32px 32px', transformBox: 'view-box' }}
        {...(animate ? { initial: { scale: 0, rotate: -45 }, animate: { scale: 1, rotate: 0 }, transition: { delay: delay + 1.95, type: 'spring', stiffness: 320, damping: 14 } } : still)} />
    </svg>
  )
}
