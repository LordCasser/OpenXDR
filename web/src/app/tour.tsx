import { Tour, type TourProps, type TourStepProps } from 'antd'
import { createContext, useContext, useState, type ReactNode } from 'react'
import { useI18n, type MsgKey } from '../i18n'

const TourContext = createContext<{ start: () => void; done: boolean }>({ start: () => {}, done: true })

// 菜单项与它所在分组：菜单标签上挂 data-tour，收起时没有分组就指向菜单项本身
const item = (path: string) => document.querySelector(`[data-tour="${path}"]`)?.closest<HTMLElement>('li') ?? null
const group = (path: string) => item(path)?.closest<HTMLElement>('.ant-menu-item-group') ?? item(path)
const el = (selector: string) => document.querySelector<HTMLElement>(selector)

// 界面导览：首次登录自动走一遍，之后从账号菜单、命令面板或上手清单重看。
// 指向的元素不在（窄屏抽屉没开）时 antd 会把这一步居中显示，不会卡住
const STEPS: [MsgKey, MsgKey, (() => HTMLElement | null) | null, TourStepProps['placement']?][] = [
  ['tourWelcomeTitle', 'tourWelcomeDesc', null],
  ['tourGroupTitle', 'tourGroupDesc', () => el('.app-group'), 'right'],
  ['tourChatTitle', 'tourChatDesc', () => item('/chat'), 'right'],
  ['tourOverviewTitle', 'tourOverviewDesc', () => item('/overview'), 'right'],
  ['tourIncidentsTitle', 'tourIncidentsDesc', () => item('/incidents'), 'right'],
  ['tourEventsTitle', 'tourEventsDesc', () => item('/events'), 'right'],
  ['tourAssetsTitle', 'tourAssetsDesc', () => group('/assets'), 'right'],
  ['tourAutoTitle', 'tourAutoDesc', () => group('/reports'), 'right'],
  ['tourDetectTitle', 'tourDetectDesc', () => group('/rules'), 'right'],
  ['tourSearchTitle', 'tourSearchDesc', () => el('.app-search')],
  ['tourAccountTitle', 'tourAccountDesc', () => el('.sider-user'), 'rightBottom'],
]

export function TourProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [done, setDone] = useState(() => localStorage.getItem('tourDone') === '1')
  const [open, setOpen] = useState(!done)
  const [current, setCurrent] = useState(0)
  const close = () => {
    localStorage.setItem('tourDone', '1')
    setDone(true)
    setOpen(false)
  }
  const steps: TourProps['steps'] = STEPS.map(([title, desc, target, placement]) => ({
    title: t(title),
    description: t(desc),
    // antd 的类型不认 () => HTMLElement | null，运行时找不到元素会居中显示
    target: (target ?? undefined) as (() => HTMLElement) | undefined,
    placement,
  }))
  return (
    <TourContext.Provider value={{ start: () => { setCurrent(0); setOpen(true) }, done }}>
      {children}
      <Tour open={open} current={current} onChange={setCurrent} onClose={close} onFinish={close} steps={steps} />
    </TourContext.Provider>
  )
}

export const useTour = () => useContext(TourContext)
