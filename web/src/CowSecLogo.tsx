// CowSec's mascot: a cow on guard inside a security shield, with a wardrobe of seasonal
// looks. Each look is a hat on her head and a charm on her collar; both stay inside the
// shield so she reads at sidebar and favicon sizes. Generated from docs/assets/mascot/*.svg.
import { useEffect, useId, useMemo, useState } from 'react';

const BASE = "<defs><linearGradient id=\"cowsecBg\" x1=\"0\" y1=\"0\" x2=\"64\" y2=\"64\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" style=\"stop-color:var(--mascot-tile-a,#0b1530)\" /><stop offset=\"100%\" style=\"stop-color:var(--mascot-tile-b,#050a18)\" /></linearGradient><linearGradient id=\"cowsecRim\" x1=\"0\" y1=\"0\" x2=\"64\" y2=\"64\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" stop-color=\"#34d399\" stop-opacity=\"0.9\" /><stop offset=\"50%\" stop-color=\"#38bdf8\" stop-opacity=\"0.5\" /><stop offset=\"100%\" stop-color=\"#818cf8\" stop-opacity=\"0.85\" /></linearGradient><linearGradient id=\"cowsecShield\" x1=\"32\" y1=\"6\" x2=\"32\" y2=\"60\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" stop-color=\"#10b981\" /><stop offset=\"55%\" stop-color=\"#0ea5e9\" /><stop offset=\"100%\" stop-color=\"#4f46e5\" /></linearGradient><linearGradient id=\"cowsecShieldInner\" x1=\"32\" y1=\"10\" x2=\"32\" y2=\"56\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" style=\"stop-color:var(--mascot-inner-a,#0f2a3a)\" /><stop offset=\"100%\" style=\"stop-color:var(--mascot-inner-b,#0b1530)\" /></linearGradient><linearGradient id=\"cowsecHead\" x1=\"32\" y1=\"18\" x2=\"32\" y2=\"50\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" stop-color=\"#ffffff\" /><stop offset=\"100%\" stop-color=\"#e2e8f0\" /></linearGradient><linearGradient id=\"cowsecMuzzle\" x1=\"32\" y1=\"38\" x2=\"32\" y2=\"50\" gradientUnits=\"userSpaceOnUse\"><stop offset=\"0%\" stop-color=\"#fbcfe8\" /><stop offset=\"100%\" stop-color=\"#f472b6\" /></linearGradient></defs><rect width=\"64\" height=\"64\" rx=\"16\" fill=\"url(#cowsecBg)\" /><rect x=\"0.75\" y=\"0.75\" width=\"62.5\" height=\"62.5\" rx=\"15.25\" style=\"stroke:var(--mascot-rim,rgba(255,255,255,0.08))\" stroke-width=\"1.5\" /><path d=\"M32 5.5L52 12.5V30C52 43 43.5 52.5 32 58.5C20.5 52.5 12 43 12 30V12.5L32 5.5Z\" fill=\"url(#cowsecShield)\" /><path d=\"M32 8.6L49.2 14.6V30.2C49.2 41.6 41.9 50 32 55.4C22.1 50 14.8 41.6 14.8 30.2V14.6L32 8.6Z\" fill=\"url(#cowsecShieldInner)\" /><path d=\"M32 9.2L48.6 15V21C42 17.5 37 16.2 32 16.2C27 16.2 22 17.5 15.4 21V15L32 9.2Z\" fill=\"#ffffff\" fill-opacity=\"0.06\" /><path d=\"M22.6 20.8C21 19.5 20.5 17.6 21.3 16.2C22.1 17.7 23.3 18.6 24.8 19.1Z\" fill=\"#fef3c7\" stroke=\"#d6a548\" stroke-width=\"0.55\" stroke-linejoin=\"round\"/><path d=\"M41.4 20.8C43 19.5 43.5 17.6 42.7 16.2C41.9 17.7 40.7 18.6 39.2 19.1Z\" fill=\"#fef3c7\" stroke=\"#d6a548\" stroke-width=\"0.55\" stroke-linejoin=\"round\"/><ellipse cx=\"18.6\" cy=\"25.4\" rx=\"4.2\" ry=\"2.4\" transform=\"rotate(-24 18.6 25.4)\" fill=\"url(#cowsecHead)\" stroke=\"#94a3b8\" stroke-width=\"0.5\" /><ellipse cx=\"18.9\" cy=\"25.3\" rx=\"2.4\" ry=\"1.15\" transform=\"rotate(-24 18.9 25.3)\" fill=\"#f9a8d4\" /><ellipse cx=\"45.4\" cy=\"25.4\" rx=\"4.2\" ry=\"2.4\" transform=\"rotate(24 45.4 25.4)\" fill=\"url(#cowsecHead)\" stroke=\"#94a3b8\" stroke-width=\"0.5\" /><ellipse cx=\"45.1\" cy=\"25.3\" rx=\"2.4\" ry=\"1.15\" transform=\"rotate(24 45.1 25.3)\" fill=\"#f9a8d4\" /><path d=\"M32 18.2C39.8 18.2 43.4 23.4 43.4 30.4C43.4 34.4 42.2 37.4 40.6 39.6L23.4 39.6C21.8 37.4 20.6 34.4 20.6 30.4C20.6 23.4 24.2 18.2 32 18.2Z\" fill=\"url(#cowsecHead)\" /><path d=\"M24.2 22.4C26.4 21.2 28.6 22 28.8 24C29 26 27 27.4 25.2 26.8C23.8 26.3 22.9 23.9 24.2 22.4Z\" fill=\"#0f172a\" /><path d=\"M38.6 22C40.8 22.6 41.9 25 40.9 26.6C40 28 38 27.9 37.2 26.6C36.4 25.2 37.1 22.3 38.6 22Z\" fill=\"#0f172a\" /><path d=\"M29.2 18.9C30.2 17.2 31.4 16.9 32.3 18.3C33.1 16.8 34.6 17.1 35.1 18.9C33.9 19.6 30.6 19.7 29.2 18.9Z\" fill=\"#0f172a\" /><ellipse cx=\"27.6\" cy=\"29.6\" rx=\"1.9\" ry=\"2.3\" fill=\"#0f172a\" /><ellipse cx=\"36.4\" cy=\"29.6\" rx=\"1.9\" ry=\"2.3\" fill=\"#0f172a\" /><circle cx=\"28.2\" cy=\"28.7\" r=\"0.75\" fill=\"#ffffff\" /><circle cx=\"37\" cy=\"28.7\" r=\"0.75\" fill=\"#ffffff\" /><g stroke=\"#0f172a\" stroke-width=\"0.7\" stroke-linecap=\"round\"><path d=\"M25.9 28.1L24.7 27.4\"/><path d=\"M26.4 27.4L25.6 26.4\"/><path d=\"M27.3 27.1L27 26\"/><path d=\"M38.1 28.1L39.3 27.4\"/><path d=\"M37.6 27.4L38.4 26.4\"/><path d=\"M36.7 27.1L37 26\"/></g><ellipse cx=\"24.3\" cy=\"34\" rx=\"2.2\" ry=\"1.3\" fill=\"#f472b6\" fill-opacity=\"0.35\"/><ellipse cx=\"39.7\" cy=\"34\" rx=\"2.2\" ry=\"1.3\" fill=\"#f472b6\" fill-opacity=\"0.35\"/><ellipse cx=\"32\" cy=\"41\" rx=\"9.6\" ry=\"6.4\" fill=\"url(#cowsecMuzzle)\" stroke=\"#db2777\" stroke-opacity=\"0.45\" stroke-width=\"0.6\" /><ellipse cx=\"28.6\" cy=\"40.4\" rx=\"1.4\" ry=\"1.9\" fill=\"#831843\" /><ellipse cx=\"35.4\" cy=\"40.4\" rx=\"1.4\" ry=\"1.9\" fill=\"#831843\" /><path d=\"M29.6 44.2C31 45.2 33 45.2 34.4 44.2\" stroke=\"#831843\" stroke-width=\"0.8\" stroke-linecap=\"round\" /><path d=\"M24 46.6C26.5 48.4 29.2 49.2 32 49.2C34.8 49.2 37.5 48.4 40 46.6\" stroke=\"#6366f1\" stroke-width=\"2.2\" stroke-linecap=\"round\"/>";
const DEFS = "<pattern id=\"check\" width=\"2.4\" height=\"2.4\" patternUnits=\"userSpaceOnUse\"><rect width=\"1.2\" height=\"2.4\" fill=\"#422006\"/><rect width=\"2.4\" height=\"1.2\" fill=\"#422006\" fill-opacity=\".6\"/></pattern>";
const HATS: Record<string, string> = {
 "security": "<path d=\"M22 21.2C22 15 26.4 11.6 32 11.6C37.6 11.6 42 15 42 21.2Z\" fill=\"#1e293b\" stroke=\"#0b1220\" stroke-width=\".5\"/><path d=\"M22 19.4H42V21.4H22Z\" fill=\"#4f46e5\"/><path d=\"M20.6 21.2C25 22.9 39 22.9 43.4 21.2C43 23.3 39.6 24.5 32 24.5C24.4 24.5 21 23.3 20.6 21.2Z\" fill=\"#0b1220\"/><path d=\"M32 13.6L34.8 14.6V16.8C34.8 18.5 33.7 19.6 32 20.3C30.3 19.6 29.2 18.5 29.2 16.8V14.6Z\" fill=\"#fbbf24\" stroke=\"#b45309\" stroke-width=\".35\"/><path d=\"M30.9 16.9L31.7 17.7L33.2 16.1\" stroke=\"#7c2d12\" stroke-width=\".55\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>",
 "plain": "",
 "santa": "<path d=\"M22.4 21.4C22.4 15.6 26.8 11.8 32.6 11.8C37.6 11.8 41 13.6 43.4 17.2C44.6 19 45 21.4 44.2 24.2L41.6 22.4L41.6 21.4Z\" fill=\"#dc2626\"/><path d=\"M32.6 11.8C37.6 11.8 41 13.6 43.4 17.2L42 18C39.8 15.4 36.8 13.8 33 13.6Z\" fill=\"#ffffff\" fill-opacity=\".2\"/><rect x=\"21\" y=\"19.6\" width=\"22\" height=\"4.2\" rx=\"2.1\" fill=\"#f8fafc\" stroke=\"#cbd5e1\" stroke-width=\".4\"/><circle cx=\"44.2\" cy=\"25.2\" r=\"2.4\" fill=\"#f8fafc\" stroke=\"#cbd5e1\" stroke-width=\".4\"/>",
 "newyear": "<path d=\"M27.6 20.6L32 7.8L36.4 20.6Z\" fill=\"#a855f7\" stroke=\"#6b21a8\" stroke-width=\".4\"/><path d=\"M29.3 15.6L34.7 15.6M30.6 11.8L33.4 11.8\" stroke=\"#fde047\" stroke-width=\"1.1\" stroke-linecap=\"round\"/><circle cx=\"32\" cy=\"7.6\" r=\"1.8\" fill=\"#fde047\"/><rect x=\"22.5\" y=\"13\" width=\"1.5\" height=\"1.5\" rx=\".3\" fill=\"#f472b6\" transform=\"rotate(20 23.2 13.7)\"/><rect x=\"40\" y=\"12\" width=\"1.5\" height=\"1.5\" rx=\".3\" fill=\"#38bdf8\" transform=\"rotate(-25 40.7 12.7)\"/><circle cx=\"25.5\" cy=\"9.6\" r=\".85\" fill=\"#34d399\"/><circle cx=\"38.6\" cy=\"9\" r=\".85\" fill=\"#fb7185\"/>",
 "valentine": "<path d=\"M23.2 30.4C21.2 28.6 22 26 24.2 26C25.3 26 26.2 26.6 26.7 27.4C27.2 26.6 28.1 26 29.2 26C31.4 26 32 28.6 30.2 30.4L26.7 33.6Z\" fill=\"#f43f5e\" fill-opacity=\".92\"/><path d=\"M33.8 30.4C31.8 28.6 32.6 26 34.8 26C35.9 26 36.8 26.6 37.3 27.4C37.8 26.6 38.7 26 39.8 26C42 26 42.6 28.6 40.8 30.4L37.3 33.6Z\" fill=\"#f43f5e\" fill-opacity=\".92\"/><path d=\"M30.6 28.4H33.4\" stroke=\"#9f1239\" stroke-width=\".8\"/>",
 "easter": "<path d=\"M26.2 20.6C23.6 16 23.4 11 25.6 9.2C27.8 10.2 28.8 15 28.4 19.8Z\" fill=\"#f8fafc\" stroke=\"#cbd5e1\" stroke-width=\".5\"/><path d=\"M26.3 18.6C25 15.4 25 12.2 25.8 11C26.8 12 27.2 15.2 27.1 18.2Z\" fill=\"#f9a8d4\"/><path d=\"M37.8 20.6C40.4 16 40.6 11 38.4 9.2C36.2 10.2 35.2 15 35.6 19.8Z\" fill=\"#f8fafc\" stroke=\"#cbd5e1\" stroke-width=\".5\"/><path d=\"M37.7 18.6C39 15.4 39 12.2 38.2 11C37.2 12 36.8 15.2 36.9 18.2Z\" fill=\"#f9a8d4\"/>",
 "summer": "<path d=\"M23.4 27.4H30.2C30.2 31.2 28.6 32.6 26.6 32.6C24.6 32.6 23.4 31 23.4 27.4Z\" fill=\"#0f172a\"/><path d=\"M33.8 27.4H40.6C40.6 31 39.4 32.6 37.4 32.6C35.4 32.6 33.8 31.2 33.8 27.4Z\" fill=\"#0f172a\"/><path d=\"M22 27.4H42\" stroke=\"#0f172a\" stroke-width=\"1.1\" stroke-linecap=\"round\"/><path d=\"M24.6 28.4L26.6 30.6M35 28.4L37 30.6\" stroke=\"#38bdf8\" stroke-opacity=\".7\" stroke-width=\".8\" stroke-linecap=\"round\"/><g transform=\"translate(41.6 19)\"><g fill=\"#f472b6\"><circle cy=\"-2.4\" r=\"1.4\"/><circle cx=\"2.3\" cy=\"-.7\" r=\"1.4\"/><circle cx=\"1.4\" cy=\"1.9\" r=\"1.4\"/><circle cx=\"-1.4\" cy=\"1.9\" r=\"1.4\"/><circle cx=\"-2.3\" cy=\"-.7\" r=\"1.4\"/></g><circle r=\"1.2\" fill=\"#fde047\"/></g>",
 "halloween": "<path d=\"M19.6 21.4C23.6 19.4 40.4 19.4 44.4 21.4C42.2 23.2 21.8 23.2 19.6 21.4Z\" fill=\"#1e1b4b\"/><path d=\"M24.4 20.6C25.6 15.6 28 11.8 30.8 9.4C32.8 7.8 35.6 7.2 37.6 8.6C35.4 9 34.2 10.6 34.6 12.8L39.6 20.6Z\" fill=\"#4c1d95\"/><path d=\"M24.8 18.6H39.4\" stroke=\"#f97316\" stroke-width=\"1.9\"/>",
 "detective": "<path d=\"M21.6 21.4C21.6 15.4 26.2 11.8 32 11.8C37.8 11.8 42.4 15.4 42.4 21.4Z\" fill=\"#a16207\"/><path d=\"M21.6 21.4C21.6 15.4 26.2 11.8 32 11.8C37.8 11.8 42.4 15.4 42.4 21.4Z\" fill=\"url(#check)\" fill-opacity=\".35\"/><path d=\"M20 21.4C23 23.1 41 23.1 44 21.4L42.8 23.8C37.6 24.9 26.4 24.9 21.2 23.8Z\" fill=\"#854d0e\"/><path d=\"M31.2 12C31.2 10.6 32.8 10.6 32.8 12\" stroke=\"#854d0e\" stroke-width=\"1.2\"/>"
};
const CHARMS: Record<string, string> = {
 "bell": "<path d=\"M30.4 49.6V48.9C30.4 47.9 31.1 47.2 32 47.2C32.9 47.2 33.6 47.9 33.6 48.9V49.6\" stroke=\"#fcd34d\" stroke-width=\"0.9\"/><path d=\"M29.6 49.4H34.4L35.3 53.6C35.4 54.1 35.1 54.4 34.6 54.4H29.4C28.9 54.4 28.6 54.1 28.7 53.6Z\" fill=\"#fbbf24\" stroke=\"#b45309\" stroke-width=\"0.4\"/><circle cx=\"32\" cy=\"51.3\" r=\"0.75\" fill=\"#7c2d12\"/><path d=\"M32 51.6V52.9\" stroke=\"#7c2d12\" stroke-width=\"0.6\" stroke-linecap=\"round\"/>",
 "bauble": "<path d=\"M31.2 48.2H32.8V49.6H31.2Z\" fill=\"#cbd5e1\"/><circle cx=\"32\" cy=\"52\" r=\"2.9\" fill=\"#dc2626\" stroke=\"#7f1d1d\" stroke-width=\".4\"/><path d=\"M29.4 51.6C31 52.4 33 52.4 34.6 51.6\" stroke=\"#fde047\" stroke-width=\".7\"/><circle cx=\"31\" cy=\"50.9\" r=\".7\" fill=\"#ffffff\" fill-opacity=\".7\"/>",
 "pumpkin": "<ellipse cx=\"32\" cy=\"52\" rx=\"3.4\" ry=\"2.8\" fill=\"#f97316\" stroke=\"#9a3412\" stroke-width=\".4\"/><path d=\"M32 49.2V48.2\" stroke=\"#15803d\" stroke-width=\"1\" stroke-linecap=\"round\"/><path d=\"M30.4 51.4L31 50.8L31.6 51.4M32.4 51.4L33 50.8L33.6 51.4M30.6 52.9C31.5 53.6 32.5 53.6 33.4 52.9\" stroke=\"#7c2d12\" stroke-width=\".5\" fill=\"none\"/>",
 "egg": "<ellipse cx=\"32\" cy=\"52\" rx=\"2.5\" ry=\"3.1\" fill=\"#a7f3d0\" stroke=\"#059669\" stroke-width=\".4\"/><path d=\"M29.7 51.6L30.9 50.8L32 51.6L33.1 50.8L34.3 51.6\" stroke=\"#059669\" stroke-width=\".55\" fill=\"none\"/><circle cx=\"31.2\" cy=\"53.4\" r=\".5\" fill=\"#f472b6\"/><circle cx=\"32.9\" cy=\"53.6\" r=\".5\" fill=\"#f472b6\"/>",
 "heartlock": "<path d=\"M30.6 49.6V48.9C30.6 48 31.2 47.4 32 47.4C32.8 47.4 33.4 48 33.4 48.9V49.6\" stroke=\"#fcd34d\" stroke-width=\".8\"/><path d=\"M29.5 51.2C28.4 50 29 48.9 30.3 48.9C31 48.9 31.6 49.3 32 49.9C32.4 49.3 33 48.9 33.7 48.9C35 48.9 35.6 50 34.5 51.2L32 54Z\" fill=\"#f43f5e\" stroke=\"#9f1239\" stroke-width=\".4\"/><circle cx=\"32\" cy=\"50.9\" r=\".55\" fill=\"#881337\"/>",
 "star": "<path d=\"M32 48.2L33.1 50.6L35.6 50.9L33.7 52.6L34.2 55L32 53.8L29.8 55L30.3 52.6L28.4 50.9L30.9 50.6Z\" fill=\"#fde047\" stroke=\"#ca8a04\" stroke-width=\".4\"/>"
};

export type Look = 'security' | 'plain' | 'newyear' | 'valentine' | 'easter' | 'summer' | 'halloween' | 'santa' | 'detective';
export const LOOKS: { id: Look; name: string; when: string; hat: string; charm: string }[] = [
 {
  "id": "security",
  "name": "Head of Security",
  "when": "Every day: on duty",
  "hat": "security",
  "charm": "bell"
 },
 {
  "id": "plain",
  "name": "Off duty",
  "when": "Optional, no hat",
  "hat": "plain",
  "charm": "bell"
 },
 {
  "id": "newyear",
  "name": "Party Moo",
  "when": "31 Dec to 2 Jan",
  "hat": "newyear",
  "charm": "star"
 },
 {
  "id": "valentine",
  "name": "Love Lock",
  "when": "10 to 14 Feb",
  "hat": "valentine",
  "charm": "heartlock"
 },
 {
  "id": "easter",
  "name": "Bunny Moo",
  "when": "Good Friday to Easter Monday",
  "hat": "easter",
  "charm": "egg"
 },
 {
  "id": "summer",
  "name": "Cool Moo",
  "when": "July and August",
  "hat": "summer",
  "charm": "bell"
 },
 {
  "id": "halloween",
  "name": "Witchy Moo",
  "when": "24 to 31 Oct",
  "hat": "halloween",
  "charm": "pumpkin"
 },
 {
  "id": "santa",
  "name": "Santa Moo",
  "when": "1 to 26 Dec",
  "hat": "santa",
  "charm": "bauble"
 },
 {
  "id": "detective",
  "name": "Detective Moo",
  "when": "Optional extra",
  "hat": "detective",
  "charm": "bell"
 }
];

// Easter Sunday (anonymous Gregorian algorithm)
function easter(y: number): Date {
  const a = y % 19, b = Math.floor(y / 100), c = y % 100, d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30, i = Math.floor(c / 4), k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31), day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(y, month - 1, day);
}

/** The look for a date: seasonal when one applies, otherwise on duty. */
export function seasonalLook(now = new Date()): Look {
  const m = now.getMonth() + 1, d = now.getDate();
  if ((m === 12 && d === 31) || (m === 1 && d <= 2)) return 'newyear';
  if (m === 2 && d >= 10 && d <= 14) return 'valentine';
  const e = easter(now.getFullYear()), day = 86400000, t = new Date(now.getFullYear(), m - 1, d).getTime();
  if (t >= e.getTime() - 2 * day && t <= e.getTime() + day) return 'easter';
  if (m === 7 || m === 8) return 'summer';
  if (m === 10 && d >= 24) return 'halloween';
  if (m === 12 && d <= 26) return 'santa';
  return 'security';
}

const PREF = 'cowsec_mascot';
/** "auto" follows the calendar; anything else pins one look. */
export function mascotPreference(): Look | 'auto' {
  try {
    const v = localStorage.getItem(PREF);
    return v && (v === 'auto' || LOOKS.some((l) => l.id === v)) ? (v as Look | 'auto') : 'auto';
  } catch {
    return 'auto';
  }
}
export function setMascotPreference(v: Look | 'auto') {
  try {
    localStorage.setItem(PREF, v);
  } catch {
    /* storage unavailable */
  }
  window.dispatchEvent(new Event('cowsec-mascot'));
}

export default function CowSecLogo({ className = 'w-11 h-11 drop-shadow-[0_4px_12px_rgba(56,189,248,0.4)]', look }: { className?: string; look?: Look }) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, '');
  const [, bump] = useState(0);
  useEffect(() => {
    const on = () => bump((n) => n + 1);
    window.addEventListener('cowsec-mascot', on);
    return () => window.removeEventListener('cowsec-mascot', on);
  }, []);
  const pref = look ?? (mascotPreference() === 'auto' ? seasonalLook() : (mascotPreference() as Look));
  const markup = useMemo(() => {
    const l = LOOKS.find((x) => x.id === pref) ?? LOOKS[0];
    const svg = BASE.replace('<defs>', '<defs>' + DEFS) + (CHARMS[l.charm] ?? '') + (HATS[l.hat] ?? '');
    return svg.replace(/id="([^"]+)"/g, `id="${uid}$1"`).replace(/url\(#([^)]+)\)/g, `url(#${uid}$1)`);
  }, [pref, uid]);
  const name = LOOKS.find((x) => x.id === pref)?.name ?? 'CowSec';
  return <svg viewBox="0 0 64 64" className={className} fill="none" role="img" aria-label={`Bessie the Bouncer: ${name}`} dangerouslySetInnerHTML={{ __html: markup }} />;
}
