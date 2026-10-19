import { ArrowRightOutlined, CheckOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Checkbox, ConfigProvider, Empty, Input, Space, Tag, Typography, theme } from 'antd'
import { AnimatePresence, motion, useReducedMotion, type Variants } from 'motion/react'
import { Component, useCallback, useEffect, useState, type ReactNode } from 'react'
import { acceptAgreement, createGroup, fetchAssets, finishOnboarding, type SetupState } from '../api'
import { useSession } from '../app/session'
import { AddHostModal } from '../components/AddHostModal'
import { AIModelSettings } from '../components/AISettings'
import { errText } from '../components/format'
import { NotifySettingsCard } from '../pages/SettingsPage'
import { useI18n } from '../i18n'
import BlackHole from './BlackHole'
import { AGREEMENT, COMPANIES, COPY, type Copy } from './copy'
import './welcome.css'

type Phase = 'present' | 'hero' | 'agreement' | 'wizard'
const STEP_KEYS = ['ai', 'project', 'assets', 'webhook'] as const

// 与项目主页同一套缓动与入场节奏（pages/src/components/blocks/hero-24.tsx）
const EASE = [0.22, 1, 0.36, 1] as const
const container: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.09, delayChildren: 0.08 } } }
const item: Variants = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: EASE } } }
const headline: Variants = {
  hidden: { opacity: 0, y: 26, filter: 'blur(10px)' },
  show: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.85, ease: EASE } },
}
const panel = {
  initial: { opacity: 0, y: 24, scale: 0.98, filter: 'blur(8px)' },
  animate: { opacity: 1, y: 0, scale: 1, filter: 'blur(0px)', transition: { duration: 0.7, ease: EASE } },
  exit: { opacity: 0, y: -16, filter: 'blur(6px)', transition: { duration: 0.35, ease: EASE } },
}

// 欢迎页整体用暗色，不继承控制台的亮色 token；主色取主页的黑白，不用默认蓝
const DARK = {
  inherit: false,
  algorithm: theme.darkAlgorithm,
  token: { colorPrimary: '#f5f5f5', colorTextLightSolid: '#0a0a0a', colorBgContainer: 'rgba(255,255,255,0.04)', colorBgElevated: '#171717', borderRadius: 10 },
}

// 首次安装的全屏欢迎：出品 → 欢迎 → 用户协议 → 四步引导。升级上来的实例只补同意协议
export function WelcomeFlow({ setup }: { setup: SetupState }) {
  const { locale } = useI18n()
  const c = COPY[locale]
  const reduce = useReducedMotion()
  const [phase, setPhase] = useState<Phase>(setup.accepted ? 'wizard' : 'present')
  const toHero = useCallback(() => setPhase(p => (p === 'present' ? 'hero' : p)), [])

  return (
    <ConfigProvider theme={DARK}>
    <div className="wl-root">
      <Backdrop dim={phase === 'present' ? 1 : phase === 'hero' ? 0 : 0.55} speed={reduce ? 0 : 0.72} />
      <AnimatePresence mode="wait">
        {phase === 'present' && <Present key="present" c={c} onDone={toHero} fast={!!reduce} />}
        {phase === 'hero' && <Hero key="hero" c={c} onStart={() => setPhase('agreement')} />}
        {phase === 'agreement' && <Agreement key="agreement" c={c} setup={setup} onAccepted={() => setPhase('wizard')} />}
        {phase === 'wizard' && <Wizard key="wizard" c={c} />}
      </AnimatePresence>
      {phase !== 'present' && <Rights c={c} />}
    </div>
    </ConfigProvider>
  )
}

// 黑洞背景常驻，各阶段只调遮罩深浅；浏览器没有 WebGL 时退回纯色渐变
function Backdrop({ dim, speed }: { dim: number; speed: number }) {
  return (
    <div className="wl-backdrop" aria-hidden>
      <GLBoundary>
        <BlackHole width="100%" height="100%" speed={speed} zoom={1.48} particleCount={16} orbSize={0.76} glow={0.075}
          contrast={2.7} distanceFade={0.32} mirrorSplits={2} warpEnabled backgroundColor="#0a0a0a" opacity={0.96} cursorInteraction={false} />
      </GLBoundary>
      <div className="wl-shade-side" />
      <div className="wl-shade-bottom" />
      <motion.div className="wl-dim" animate={{ opacity: dim }} transition={{ duration: 1.2, ease: EASE }} />
    </div>
  )
}

class GLBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() { return this.state.failed ? <div className="wl-fallback" /> : this.props.children }
}

// 片头：「OpenXDR 开发组 presents」，再亮出名字。点哪都能跳过
function Present({ c, onDone, fast }: { c: Copy; onDone: () => void; fast: boolean }) {
  useEffect(() => {
    const timer = setTimeout(onDone, fast ? 600 : 4600)
    return () => clearTimeout(timer)
  }, [onDone, fast])
  return (
    <motion.div className="wl-present" onClick={onDone} exit={{ opacity: 0, transition: { duration: 0.8 } }}>
      <motion.div className="wl-present-team" initial={{ opacity: 0, letterSpacing: '0.6em' }} animate={{ opacity: [0, 1, 1, 0], letterSpacing: '0.32em' }}
        transition={{ duration: 2.4, times: [0, 0.3, 0.75, 1], ease: 'easeOut' }}>
        {c.team}
        <motion.span className="wl-present-presents" initial={{ opacity: 0 }} animate={{ opacity: [0, 0, 1, 0] }} transition={{ duration: 2.4, times: [0, 0.35, 0.6, 1] }}>
          {c.presents}
        </motion.span>
      </motion.div>
      <motion.div className="wl-present-name" initial={{ opacity: 0, scale: 0.92, filter: 'blur(16px)' }} animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
        transition={{ delay: 2.5, duration: 1.4, ease: EASE }}>
        Open<span>XDR</span>
      </motion.div>
      <motion.div className="wl-present-skip" initial={{ opacity: 0 }} animate={{ opacity: 0.5 }} transition={{ delay: 1 }}>{c.skipIntro}</motion.div>
    </motion.div>
  )
}

function Hero({ c, onStart }: { c: Copy; onStart: () => void }) {
  return (
    <motion.section className="wl-hero" variants={container} initial="hidden" animate="show" exit={{ opacity: 0, x: -40, filter: 'blur(8px)', transition: { duration: 0.45 } }}>
      <motion.div variants={item} className="wl-badge"><span className="wl-ping"><i /><b /></span>{c.badge}</motion.div>
      <motion.h1 variants={headline} className="wl-headline">{c.headline}<br /><span>{c.headlineAccent}</span></motion.h1>
      <motion.p variants={item} className="wl-desc">{c.description}</motion.p>
      <motion.div variants={item}>
        <button type="button" className="wl-cta" onClick={onStart} autoFocus>{c.start}<ArrowRightOutlined /></button>
      </motion.div>
      <motion.div variants={item} className="wl-pillars">{c.pillars.map(p => <span key={p}>{p}</span>)}</motion.div>
    </motion.section>
  )
}

function Agreement({ c, setup, onAccepted }: { c: Copy; setup: SetupState; onAccepted: () => void }) {
  const { locale } = useI18n()
  const { message } = App.useApp()
  const client = useQueryClient()
  const { signOut } = useSession()
  const { t } = useI18n()
  const [checked, setChecked] = useState(false)
  const accept = useMutation({
    mutationFn: () => acceptAgreement(setup.agreementVersion),
    // 升级上来的实例不走引导，同意后直接进控制台
    onSuccess: () => (setup.onboarded ? client.invalidateQueries({ queryKey: ['setup'] }) : onAccepted()),
    onError: e => message.error(errText(e, t)),
  })
  return (
    <motion.section className="wl-panel wl-agreement" {...panel}>
      <header>
        <h2>{c.agreementTitle}</h2>
        <Tag bordered={false}>{c.version} {setup.agreementVersion}</Tag>
      </header>
      <p className="wl-lead">{c.agreementLead}</p>
      <div className="wl-terms" tabIndex={0}>
        {AGREEMENT[locale].map(([title, body]) => <section key={title}><h3>{title}</h3><p>{body}</p></section>)}
      </div>
      <footer>
        <Checkbox checked={checked} onChange={e => setChecked(e.target.checked)}>{c.agreementCheck}</Checkbox>
        <Space wrap>
          <Button type="text" onClick={() => signOut()}>{c.decline}</Button>
          <Button type="primary" size="large" disabled={!checked} loading={accept.isPending} onClick={() => accept.mutate()}>{c.agree}</Button>
        </Space>
      </footer>
    </motion.section>
  )
}

// 四步引导：每步都能跳过，跳过的步骤记进审计；表单直接复用设置页与资产页的组件
function Wizard({ c }: { c: Copy }) {
  const client = useQueryClient()
  const { message } = App.useApp()
  const { t } = useI18n()
  const [step, setStep] = useState(0)
  const [skipped, setSkipped] = useState<string[]>([])
  const finish = useMutation({
    mutationFn: (s: string[]) => finishOnboarding(s),
    onSuccess: () => client.invalidateQueries({ queryKey: ['setup'] }),
    onError: e => message.error(errText(e, t)),
  })
  const last = step === STEP_KEYS.length - 1
  const advance = (skip: boolean) => {
    const next = skip ? [...new Set([...skipped, STEP_KEYS[step]])] : skipped.filter(k => k !== STEP_KEYS[step])
    setSkipped(next)
    if (last) finish.mutate(next)
    else setStep(step + 1)
  }

  return (
    <motion.section className="wl-wizard" {...panel}>
      <nav className="wl-rail" aria-label={c.steps.join(' / ')}>
        {c.steps.map((name, i) => (
          <button key={name} type="button" className={`wl-rail-step${i === step ? ' is-current' : ''}${i < step ? ' is-past' : ''}`} onClick={() => setStep(i)} aria-current={i === step ? 'step' : undefined}>
            <span className="wl-rail-mark">{i < step ? (skipped.includes(STEP_KEYS[i]) ? '–' : <CheckOutlined />) : i + 1}</span>
            <span>{name}</span>
            {i === step && <motion.span layoutId="wl-rail-glow" className="wl-rail-glow" transition={{ duration: 0.5, ease: EASE }} />}
          </button>
        ))}
        <Button type="link" className="wl-skip-all" loading={finish.isPending} onClick={() => finish.mutate([...STEP_KEYS])}>{c.skipAll}</Button>
      </nav>
      <div className="wl-panel wl-step">
        <AnimatePresence mode="wait">
          <motion.div key={step} initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0, transition: { duration: 0.45, ease: EASE } }} exit={{ opacity: 0, x: -24, transition: { duration: 0.2 } }}>
            <h2>{c.steps[step]}</h2>
            <p className="wl-lead">{c.stepHints[step]}</p>
            <div className="wl-step-body">
              {step === 0 && <AIModelSettings />}
              {step === 1 && <ProjectStep c={c} />}
              {step === 2 && <AssetStep c={c} />}
              {step === 3 && <NotifySettingsCard />}
            </div>
          </motion.div>
        </AnimatePresence>
        <footer>
          <Typography.Text className="wl-later">{c.later}</Typography.Text>
          <Space wrap>
            {step > 0 && <Button type="text" onClick={() => setStep(step - 1)}>{c.back}</Button>}
            <Button onClick={() => advance(true)} disabled={finish.isPending}>{c.skip}</Button>
            <Button type="primary" size="large" loading={finish.isPending} onClick={() => advance(false)}>{last ? c.finish : c.next}</Button>
          </Space>
        </footer>
      </div>
    </motion.section>
  )
}

function ProjectStep({ c }: { c: Copy }) {
  const { groups } = useSession()
  const client = useQueryClient()
  const { message } = App.useApp()
  const { t } = useI18n()
  const [name, setName] = useState('')
  const create = useMutation({
    mutationFn: () => createGroup(name.trim()),
    onSuccess: async g => {
      await client.invalidateQueries({ queryKey: ['groups'] })
      message.success(c.groupCreated.replace('{name}', g.name))
      setName('')
    },
    onError: e => message.error(errText(e, t)),
  })
  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <Space.Compact style={{ width: '100%', maxWidth: 480 }}>
        <Input size="large" aria-label={c.groupName} placeholder={c.groupPlaceholder} value={name} maxLength={64}
          onChange={e => setName(e.target.value)} onPressEnter={() => name.trim() && create.mutate()} />
        <Button size="large" type="primary" disabled={!name.trim()} loading={create.isPending} onClick={() => create.mutate()}>{c.groupCreate}</Button>
      </Space.Compact>
      <div>
        <Typography.Text type="secondary">{c.groupExisting}</Typography.Text>
        <div className="wl-chips">
          {groups.length ? groups.map(g => <Tag key={g.id} bordered={false} color="blue">{g.name}</Tag>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={c.groupNone} />}
        </div>
      </div>
    </Space>
  )
}

function AssetStep({ c }: { c: Copy }) {
  const { groups } = useSession()
  const [open, setOpen] = useState(false)
  // 执行安装命令后主机几秒内注册上来，这里轮询着等它出现
  const assets = useQuery({ queryKey: ['assets'], queryFn: fetchAssets, refetchInterval: 5000 })
  const n = assets.data?.filter(a => a.agentId).length ?? 0
  if (!groups.length) return <Typography.Text type="warning">{c.hostNeedGroup}</Typography.Text>
  return (
    <Space orientation="vertical" size="large">
      <Button size="large" type="primary" onClick={() => setOpen(true)}>{c.hostOpen}</Button>
      <Typography.Text type={n ? 'success' : 'secondary'}>{n ? c.hostCount.replace('{n}', String(n)) : c.hostWaiting}</Typography.Text>
      <AddHostModal open={open} onClose={() => setOpen(false)} />
    </Space>
  )
}

function Rights({ c }: { c: Copy }) {
  return (
    <motion.footer className="wl-rights" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6, duration: 1 }}>
      © {new Date().getFullYear()} {COMPANIES.join(' · ')} {c.rights}
    </motion.footer>
  )
}

// 非管理员在管理员同意协议之前看到的等待页
export function SetupWaiting() {
  const { locale } = useI18n()
  const { signOut } = useSession()
  const c = COPY[locale]
  return (
    <ConfigProvider theme={DARK}>
    <div className="wl-root">
      <Backdrop dim={0.55} speed={0.4} />
      <motion.section className="wl-panel wl-waiting" {...panel}>
        <h2>{c.waitingTitle}</h2>
        <p className="wl-lead">{c.waitingDesc}</p>
        <Button onClick={() => signOut()}>{c.signOut}</Button>
      </motion.section>
      <Rights c={c} />
    </div>
    </ConfigProvider>
  )
}
