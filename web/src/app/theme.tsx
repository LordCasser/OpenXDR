import { App as AntApp, ConfigProvider, theme } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { createContext, useContext, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'

const ThemeContext = createContext<{ dark: boolean; toggle: () => void }>({ dark: false, toggle: () => {} })

// 亮色为主，值班大屏可切暗色；选择记在本地
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n()
  const [dark, setDark] = useState(() => localStorage.getItem('theme') === 'dark')
  const toggle = () => {
    localStorage.setItem('theme', dark ? 'light' : 'dark')
    setDark(!dark)
  }
  return (
    <ThemeContext.Provider value={{ dark, toggle }}>
      <ConfigProvider
        locale={locale === 'zh' ? zhCN : enUS}
        theme={{
          algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: { colorPrimary: '#1668dc', borderRadius: 6 },
        }}
      >
        <AntApp>{children}</AntApp>
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
