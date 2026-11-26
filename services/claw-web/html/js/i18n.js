// i18n ของ claw-web — convention เดียวกับทุกแอปใน POC:
// cookie `lang` (en|th, default th, อายุ 1 ปี) · `?lang=en|th` ตั้งค่าและจำลง cookie
export function detectLang() {
  const query = new URLSearchParams(location.search).get('lang');
  if (query === 'en' || query === 'th') {
    document.cookie = `lang=${query}; path=/; max-age=31536000; samesite=lax`;
    return { lang: query, fromQuery: true };
  }
  const match = document.cookie.match(/(?:^|;\s*)lang=(en|th)/);
  return { lang: match ? match[1] : 'th', fromQuery: false };
}

export const t = (lang, thai, english) => (lang === 'en' ? english : thai);
