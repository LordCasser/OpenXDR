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
  const panel = dark ? '#121b2c' : '#ffffff'
  return (
    <ThemeContext.Provider value={{ dark, toggle }}>
      <ConfigProvider
        locale={locale === 'zh' ? zhCN : enUS}
        // 两个汉字的按钮不插空格：「保存」「关闭」和其他按钮读起来一致
        button={{ autoInsertSpace: false }}
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
            ...(dark && { colorBgContainer: panel, colorBgElevated: '#18233a', colorFillQuaternary: 'rgba(148,163,184,.06)' }),
            colorBorderSecondary: dark ? '#1f2a3d' : '#e8ecf2',
          },
          components: {
            // 侧栏与顶栏跟随主题，和内容区只用一条细线分隔（Vercel / Linear 的做法），不再单独维护一套深色导航配色
            Layout: { headerHeight: 56, headerPadding: '0 16px', headerBg: panel, lightSiderBg: panel, bodyBg: dark ? '#0b1220' : '#f3f5f9' },
            Menu: {
              itemBg: 'transparent',
              itemHeight: 34,
              itemMarginBlock: 2,
              itemMarginInline: 8,
              itemBorderRadius: 6,
              groupTitleFontSize: 12,
              iconMarginInlineEnd: 10,
              activeBarBorderWidth: 0,
            },
            Card: { headerFontSize: 15, headerHeight: 52 },
            Table: { headerBg: dark ? '#162033' : '#f7f9fc', headerColor: dark ? '#cbd5e1' : '#475569', cellPaddingBlock: 10, headerSplitColor: 'transparent' },
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
