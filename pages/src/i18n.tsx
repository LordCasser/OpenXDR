import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Locale = "en" | "zh-CN";

const pageMetadata = {
  en: {
    title: "OpenXDR - Onboarded means operated and secured",
    description:
      "Open-source XDR: onboard a host and it gets continuous detection, layered noise reduction, daily inspections and an AI assistant that does the work — with dangerous commands waiting for your approval.",
  },
  "zh-CN": {
    title: "OpenXDR - 纳管即运维，纳管即安全",
    description:
      "开源 XDR：主机纳管后自动获得持续检测、层层降噪、每日巡检和能动手的 AI 助手，危险命令等你批准。",
  },
} satisfies Record<Locale, { title: string; description: string }>;

function detectLocale(): Locale {
  const languages = navigator.languages.length
    ? navigator.languages
    : [navigator.language];
  return languages.some((language) => language.toLowerCase().startsWith("zh"))
    ? "zh-CN"
    : "en";
}

const LocaleContext = createContext<Locale>("en");

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(detectLocale);

  useEffect(() => {
    const syncLocale = () => setLocale(detectLocale());
    window.addEventListener("languagechange", syncLocale);
    return () => window.removeEventListener("languagechange", syncLocale);
  }, []);

  useEffect(() => {
    const metadata = pageMetadata[locale];
    document.documentElement.lang = locale;
    document.title = metadata.title;
    document
      .querySelector<HTMLMetaElement>('meta[name="description"]')
      ?.setAttribute("content", metadata.description);
  }, [locale]);

  const value = useMemo(() => locale, [locale]);
  return (
    <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
  );
}

export function useLocale() {
  return useContext(LocaleContext);
}

/** 按当前语言取一份文案，中英文成对写在调用处。 */
export function useCopy<T>(copy: Record<Locale, T>): T {
  return copy[useLocale()];
}
