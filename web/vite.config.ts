import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // 只手动拆两类：three 是懒加载页面（欢迎页 / 资产图谱）的大块，
        // react 体系版本稳定、单独成块利于长期缓存；antd 交给打包器按引用分配，
        // 硬拆成一块会把所有懒加载页面用到的组件都塞进首屏。
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/node_modules\/(three|@react-three)\//.test(id)) return 'three'
          if (/node_modules\/(react|react-dom|react-router|scheduler)\//.test(id)) return 'react'
        },
      },
    },
  },
  server: {
    proxy: {
      // 本机 8080 被占时可用 OPENXDR_API=http://localhost:18080 npm run dev
      '/api': process.env.OPENXDR_API ?? 'http://localhost:8080',
    },
  },
})
