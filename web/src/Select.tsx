// Themed dropdown that replaces the browser's native <select>: matches the console's
// palettes (dark and light), animates open, supports the keyboard and optional search.
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import { Check, ChevronDown, Search } from 'lucide-react';

export interface Option<T extends string> { value: T; label: ReactNode; hint?: string; search?: string }

export default function Select<T extends string>({
  value, onChange, options, placeholder = 'Choose…', className = '', searchable, ariaLabel, compact,
}: {
  value: T | ''; onChange: (v: T) => void; options: Option<T>[]; placeholder?: string; className?: string;
  searchable?: boolean; ariaLabel?: string; compact?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [hi, setHi] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const id = useId();
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? options.filter((o) => (o.search ?? `${o.value} ${typeof o.label === 'string' ? o.label : ''}`).toLowerCase().includes(t)) : options;
  }, [options, q]);
  const current = options.find((o) => o.value === value);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  useEffect(() => {
    if (open) setHi(Math.max(0, shown.findIndex((o) => o.value === value)));
  }, [open, shown, value]);

  const pick = (v: T) => {
    onChange(v);
    setOpen(false);
    setQ('');
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') return setOpen(false);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!open) return setOpen(true);
      setHi((h) => (e.key === 'ArrowDown' ? Math.min(shown.length - 1, h + 1) : Math.max(0, h - 1)));
    }
    if (e.key === 'Enter' && open && shown[hi]) {
      e.preventDefault();
      pick(shown[hi].value);
    }
  };

  return (
    <div ref={box} className={`relative ${className}`} onKeyDown={onKey}>
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={id}
        aria-label={ariaLabel}
        onClick={() => setOpen(!open)}
        className={`w-full flex items-center justify-between gap-2 rounded-lg border bg-slate-950/60 text-left text-white cursor-pointer transition-colors ${
          open ? 'border-sky-500' : 'border-slate-700 hover:border-slate-500'
        } ${compact ? 'px-2 py-1 text-xs' : 'px-2.5 py-1.5 text-sm'}`}
      >
        <span className={`truncate ${current ? '' : 'text-slate-500'}`}>{current ? current.label : placeholder}</span>
        <ChevronDown className={`w-3.5 h-3.5 shrink-0 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute z-50 mt-1.5 min-w-full w-max max-w-[22rem] rounded-xl border border-slate-700 bg-slate-900 shadow-2xl shadow-black/40 cs-pop origin-top overflow-hidden">
          {searchable && (
            <div className="relative border-b border-slate-800">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input autoFocus value={q} onChange={(e) => { setQ(e.target.value); setHi(0); }} placeholder="Search…"
                className="w-full bg-transparent pl-8 pr-3 py-2 text-sm text-white focus:outline-none" />
            </div>
          )}
          <ul id={id} role="listbox" className="max-h-64 overflow-y-auto py-1">
            {shown.map((o, i) => (
              <li key={o.value} role="option" aria-selected={o.value === value}
                onMouseEnter={() => setHi(i)} onClick={() => pick(o.value)}
                className={`flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer ${i === hi ? 'bg-sky-500/15 text-white' : 'text-slate-300'}`}>
                <Check className={`w-3.5 h-3.5 shrink-0 ${o.value === value ? 'text-sky-400' : 'opacity-0'}`} />
                <span className="flex-1 min-w-0">
                  <span className="block truncate">{o.label}</span>
                  {o.hint && <span className="block text-[11px] text-slate-500 truncate">{o.hint}</span>}
                </span>
              </li>
            ))}
            {!shown.length && <li className="px-3 py-2 text-sm text-slate-500">No matches</li>}
          </ul>
        </div>
      )}
    </div>
  );
}
