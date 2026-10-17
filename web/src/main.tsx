import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { SESSION_EXPIRED, Unauthorized } from './api'
import App from './App.tsx'
import { ThemeProvider } from './app/theme'
import { I18nProvider } from './i18n.tsx'
import './index.css'

const client = new QueryClient({
  defaultOptions: { queries: { retry: (n, err) => !(err instanceof Unauthorized) && n < 1, refetchOnWindowFocus: false } },
})

// 覆盖 Query、Mutation 和直接调用 API 的按钮操作；登录失败不触发过期。
window.addEventListener(SESSION_EXPIRED, () => client.setQueryData(['me'], null))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <ThemeProvider>
        <QueryClientProvider client={client}>
          <App />
        </QueryClientProvider>
      </ThemeProvider>
    </I18nProvider>
  </StrictMode>,
)
