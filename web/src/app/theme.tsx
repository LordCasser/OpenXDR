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
          token: {
            colorPrimary: '#2563eb',
            colorInfo: '#2563eb',
            colorError: '#dc2626',
            colorWarning: '#d97706',
            colorSuccess: '#16a34a',
            borderRadius: 8,
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", Inter, sans-serif',
            colorBgLayout: dark ? '#0b1220' : '#f3f5f9',
            // 暗色下卡片与弹层取同一族蓝灰，不用默认的中性灰，免得和深蓝底色打架
            ...(dark && { colorBgContainer: '#121b2c', colorBgElevated: '#18233a', colorFillQuaternary: 'rgba(148,163,184,.06)' }),
            colorBorderSecondary: dark ? '#1f2a3d' : '#e8ecf2',
          },
          components: {
            Layout: { siderBg: '#0f1a2e', headerBg: dark ? '#111a2b' : '#ffffff', bodyBg: dark ? '#0b1220' : '#f3f5f9' },
            Menu: {
              darkItemBg: '#0f1a2e',
              darkSubMenuItemBg: '#0f1a2e',
              darkItemSelectedBg: '#2563eb',
              darkItemColor: 'rgba(226,232,240,.72)',
              darkItemHoverColor: '#ffffff',
              darkGroupTitleColor: 'rgba(148,163,184,.7)',
              itemBorderRadius: 6,
              itemMarginInline: 10,
              itemHeight: 38,
            },
            Card: { headerFontSize: 15, boxShadowTertiary: '0 1px 2px rgba(15,23,42,.04), 0 1px 6px -1px rgba(15,23,42,.06)' },
            Table: { headerBg: dark ? '#162033' : '#f7f9fc', headerColor: dark ? '#cbd5e1' : '#475569', cellPaddingBlock: 12, headerSplitColor: 'transparent' },
            Statistic: { contentFontSize: 28 },
          },
        }}
      >
        <AntApp>{children}</AntApp>
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
