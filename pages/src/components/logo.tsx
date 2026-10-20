// 与控制台同一份品牌图标（web/public/favicon.svg），按部署路径取，GitHub Pages 的 /OpenXDR/ 子路径下也找得到
export function Logo({ size = 28, className = "" }: { size?: number; className?: string }) {
  return (
    <img
      src={`${import.meta.env.BASE_URL}favicon.svg`}
      width={size}
      height={size}
      alt=""
      aria-hidden
      className={`shrink-0 ${className}`}
    />
  );
}
