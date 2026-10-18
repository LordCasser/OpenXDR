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
      "Open-source XDR. Install the agent, pick a group, and detection, triage, daily checkups and response fall into place. The risky part waits for your nod.",
  },
  "zh-CN": {
    title: "OpenXDR - 纳管即运维，纳管即安全",
    description:
      "开源 XDR。装上 agent，分好组，检测、降噪、巡检与处置一次到位。真正危险的那一步，等你点头。",
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
