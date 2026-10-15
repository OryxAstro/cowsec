// Country flags from Twemoji (CC-BY 4.0), bundled with the console so they render the same on
// every OS (Windows has no flag emoji) and nothing is fetched from outside.
import { useState } from 'react';
import { Globe } from 'lucide-react';

export default function Flag({ code, className = 'w-[18px] h-[18px]' }: { code?: string; className?: string }) {
  const [broken, setBroken] = useState(false);
  const cc = (code || '').toLowerCase();
  if (!/^[a-z]{2}$/.test(cc) || broken) return <Globe className={`${className} text-slate-500 shrink-0`} />;
  return <img src={`/flags/${cc}.svg`} alt={cc.toUpperCase()} className={`${className} shrink-0 inline-block`} loading="lazy" onError={() => setBroken(true)} />;
}
