// 导航、登录页与浏览器标签共用同一份品牌图标。
export function Logo({ size = 28 }: { size?: number }) {
  return <img src="/favicon.svg" width={size} height={size} alt="OpenXDR" style={{ flexShrink: 0 }} />
}
