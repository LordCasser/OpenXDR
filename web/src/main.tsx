import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Unauthorized } from './api'
import App from './App.tsx'
import { ThemeProvider } from './app/theme'
import { I18nProvider } from './i18n.tsx'
import './index.css'

// 任何请求遇到 401 都视为会话失效：清掉当前用户，App 自动回到登录页
const expire = (err: unknown) => {
  if (err instanceof Unauthorized) client.setQueryData(['me'], null)
}
const client = new QueryClient({
  queryCache: new QueryCache({ onError: expire }),
  mutationCache: new MutationCache({ onError: expire }),
  defaultOptions: { queries: { retry: (n, err) => !(err instanceof Unauthorized) && n < 1, refetchOnWindowFocus: false } },
})

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
