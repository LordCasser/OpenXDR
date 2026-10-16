import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // 本机 8080 被占时可用 OPENXDR_API=http://localhost:18080 npm run dev
      '/api': process.env.OPENXDR_API ?? 'http://localhost:8080',
    },
  },
})
