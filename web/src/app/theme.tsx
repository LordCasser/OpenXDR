import { App as AntApp, ConfigProvider, theme } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'

export type ThemeMode = 'system' | 'light' | 'dark'

const ThemeContext = createContext<{ dark: boolean; mode: ThemeMode; setMode: (m: ThemeMode) => void; toggle: () => void }>({
  dark: false, mode: 'system', setMode: () => {}, toggle: () => {},
})

const query = '(prefers-color-scheme: dark)'
const stored = (): ThemeMode => {
  const v = localStorage.getItem('theme')
  return v === 'light' || v === 'dark' ? v : 'system'
}

// 苹果系统色：亮暗两套各自取官方值，状态色只给级别与状态用，强调色只有一个蓝
const PALETTE = {
  light: {
    primary: '#0071e3', success: '#34c759', warning: '#ff9500', error: '#ff3b30',
    layout: '#f5f5f7', panel: '#ffffff', elevated: '#ffffff',
    text: '#1d1d1f', text2: '#6e6e73', text3: '#86868b', border: '#d2d2d7', hairline: 'rgba(0,0,0,.08)',
    fill: 'rgba(0,0,0,.05)', fill2: 'rgba(0,0,0,.035)', fill3: 'rgba(0,0,0,.025)', fill4: 'rgba(0,0,0,.015)',
  },
  dark: {
    primary: '#0a84ff', success: '#30d158', warning: '#ff9f0a', error: '#ff453a',
    layout: '#000000', panel: '#1c1c1e', elevated: '#2c2c2e',
    text: '#f5f5f7', text2: '#a1a1a6', text3: '#8e8e93', border: '#3a3a3c', hairline: 'rgba(255,255,255,.1)',
    fill: 'rgba(255,255,255,.12)', fill2: 'rgba(255,255,255,.08)', fill3: 'rgba(255,255,255,.06)', fill4: 'rgba(255,255,255,.04)',
  },
}

// 外观默认跟随系统，账号菜单里可以固定成亮色或暗色；选择记在本地
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n()
  const [mode, setModeState] = useState<ThemeMode>(stored)
  const [systemDark, setSystemDark] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const m = window.matchMedia(query)
    const on = () => setSystemDark(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])
  const dark = mode === 'system' ? systemDark : mode === 'dark'
  useEffect(() => { document.documentElement.dataset.theme = dark ? 'dark' : 'light' }, [dark])
  const setMode = (m: ThemeMode) => {
    if (m === 'system') localStorage.removeItem('theme')
    else localStorage.setItem('theme', m)
    setModeState(m)
  }
  const toggle = () => setMode(dark ? 'light' : 'dark')
  const c = PALETTE[dark ? 'dark' : 'light']
  return (
    <ThemeContext.Provider value={{ dark, mode, setMode, toggle }}>
      <ConfigProvider
        locale={locale === 'zh' ? zhCN : enUS}
        // 两个汉字的按钮不插空格：「保存」「关闭」和其他按钮读起来一致
        button={{ autoInsertSpace: false }}
        // 标签一律浅色填充无描边，和苹果的胶囊标签一致
        tag={{ variant: 'filled' }}
        theme={{
          algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: {
            colorPrimary: c.primary,
            colorInfo: c.primary,
            colorLink: c.primary,
            colorError: c.error,
            colorWarning: c.warning,
            colorSuccess: c.success,
            colorText: c.text,
            colorTextSecondary: c.text2,
            colorTextTertiary: c.text3,
            colorTextQuaternary: dark ? '#636366' : '#aeaeb2',
            colorBgLayout: c.layout,
            colorBgContainer: c.panel,
            colorBgElevated: c.elevated,
            colorBorder: c.border,
            colorBorderSecondary: c.hairline,
            colorSplit: c.hairline,
            colorFill: c.fill,
            colorFillSecondary: c.fill2,
            colorFillTertiary: c.fill3,
            colorFillQuaternary: c.fill4,
            borderRadius: 10,
            borderRadiusLG: 14,
            borderRadiusSM: 6,
            fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "PingFang SC", "Hiragino Sans GB", Inter, "Segoe UI", "Microsoft YaHei", sans-serif',
            fontFamilyCode: 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace',
            // 阴影只用来分层，不制造立体感：卡片靠一条细线，弹层才有柔和投影
            boxShadow: dark ? '0 8px 28px rgba(0,0,0,.5)' : '0 8px 28px rgba(0,0,0,.12), 0 0 0 .5px rgba(0,0,0,.06)',
            boxShadowSecondary: dark ? '0 12px 40px rgba(0,0,0,.6)' : '0 12px 40px rgba(0,0,0,.14), 0 0 0 .5px rgba(0,0,0,.06)',
            boxShadowTertiary: 'none',
            controlOutline: dark ? 'rgba(10,132,255,.35)' : 'rgba(0,113,227,.25)',
            motionDurationMid: '0.18s',
          },
          components: {
            // 顶栏半透明磨砂（见 index.css），侧栏与页面同底色，只用一条细线分隔
            Layout: { headerHeight: 56, headerPadding: '0 16px', headerBg: 'transparent', lightSiderBg: c.layout, bodyBg: c.layout },
            Menu: {
              itemBg: 'transparent',
              itemHeight: 34,
              itemMarginBlock: 1,
              itemMarginInline: 8,
              itemBorderRadius: 8,
              groupTitleFontSize: 11,
              groupTitleColor: c.text3,
              iconMarginInlineEnd: 10,
              activeBarBorderWidth: 0,
              itemColor: c.text,
              itemSelectedBg: c.fill,
              itemSelectedColor: c.text,
              itemHoverBg: c.fill2,
            },
            Card: { headerFontSize: 15, headerHeight: 52, headerFontSizeSM: 14 },
            Table: {
              headerBg: 'transparent', headerColor: c.text3, headerSplitColor: 'transparent',
              borderColor: c.hairline, rowHoverBg: c.fill4, cellPaddingBlock: 11, headerSortActiveBg: 'transparent', headerSortHoverBg: 'transparent',
              rowSelectedBg: dark ? 'rgba(10,132,255,.14)' : 'rgba(0,113,227,.06)', rowSelectedHoverBg: dark ? 'rgba(10,132,255,.2)' : 'rgba(0,113,227,.09)',
            },
            // 次要按钮是浅灰底无边框（苹果的 gray 按钮），主按钮实心无投影
            Button: {
              primaryShadow: 'none', defaultShadow: 'none', dangerShadow: 'none',
              defaultBg: c.fill2, defaultBorderColor: 'transparent', defaultHoverBg: c.fill, defaultHoverBorderColor: 'transparent',
              defaultActiveBg: c.fill, defaultActiveBorderColor: 'transparent', defaultColor: c.text, defaultHoverColor: c.text,
              fontWeight: 500,
            },
            Segmented: { trackBg: c.fill2, itemSelectedBg: dark ? '#636366' : '#ffffff', trackPadding: 2 },
            Tabs: { itemColor: c.text2, inkBarColor: c.text, itemSelectedColor: c.text, itemHoverColor: c.text, titleFontSize: 14 },
            Input: { activeShadow: `0 0 0 3px ${dark ? 'rgba(10,132,255,.35)' : 'rgba(0,113,227,.2)'}` },
            Select: { activeOutlineColor: dark ? 'rgba(10,132,255,.35)' : 'rgba(0,113,227,.2)' },
            Tag: { defaultBg: c.fill2, defaultColor: c.text2 },
            Statistic: { contentFontSize: 28 },
            Modal: { titleFontSize: 17 },
            Drawer: { footerPaddingBlock: 12 },
            Tooltip: { colorBgSpotlight: dark ? '#3a3a3c' : 'rgba(29,29,31,.92)' },
          },
        }}
      >
        <AntApp>{children}</AntApp>
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
