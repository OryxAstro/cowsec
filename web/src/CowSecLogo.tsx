// CowSec mark: a cartoon cow guarding inside a security shield.
export default function CowSecLogo({ className = 'w-11 h-11 drop-shadow-[0_4px_12px_rgba(16,185,129,0.45)]' }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} fill="none">
      <defs>
        <linearGradient id="cowsecBg" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0b1530" />
          <stop offset="100%" stopColor="#050a18" />
        </linearGradient>
        <linearGradient id="cowsecRim" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#34d399" stopOpacity="0.9" />
          <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#818cf8" stopOpacity="0.85" />
        </linearGradient>
        <linearGradient id="cowsecShield" x1="32" y1="6" x2="32" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981" />
          <stop offset="55%" stopColor="#0ea5e9" />
          <stop offset="100%" stopColor="#4f46e5" />
        </linearGradient>
        <linearGradient id="cowsecShieldInner" x1="32" y1="10" x2="32" y2="56" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0f2a3a" />
          <stop offset="100%" stopColor="#0b1530" />
        </linearGradient>
        <linearGradient id="cowsecHead" x1="32" y1="18" x2="32" y2="50" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#ffffff" />
          <stop offset="100%" stopColor="#e2e8f0" />
        </linearGradient>
        <linearGradient id="cowsecMuzzle" x1="32" y1="38" x2="32" y2="50" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#fbcfe8" />
          <stop offset="100%" stopColor="#f472b6" />
        </linearGradient>
      </defs>

      {/* Tile */}
      <rect width="64" height="64" rx="16" fill="url(#cowsecBg)" />
      <rect x="1" y="1" width="62" height="62" rx="15" stroke="url(#cowsecRim)" strokeWidth="1.5" />

      {/* Shield */}
      <path d="M32 5.5L52 12.5V30C52 43 43.5 52.5 32 58.5C20.5 52.5 12 43 12 30V12.5L32 5.5Z" fill="url(#cowsecShield)" />
      <path d="M32 9.2L48.6 15V30.2C48.6 41.2 41.6 49.4 32 54.6C22.4 49.4 15.4 41.2 15.4 30.2V15L32 9.2Z" fill="url(#cowsecShieldInner)" />
      {/* Shield shine */}
      <path d="M32 9.2L48.6 15V21C42 17.5 37 16.2 32 16.2C27 16.2 22 17.5 15.4 21V15L32 9.2Z" fill="#ffffff" fillOpacity="0.06" />

      {/* Horns */}
      <path d="M21.2 21.5C18.8 19.6 18 16.6 19.2 14.6C20 17 21.9 18.5 24 19.3L21.2 21.5Z" fill="#fde68a" stroke="#f59e0b" strokeWidth="0.6" strokeLinejoin="round" />
      <path d="M42.8 21.5C45.2 19.6 46 16.6 44.8 14.6C44 17 42.1 18.5 40 19.3L42.8 21.5Z" fill="#fde68a" stroke="#f59e0b" strokeWidth="0.6" strokeLinejoin="round" />

      {/* Ears */}
      <ellipse cx="18.6" cy="25.4" rx="4.2" ry="2.4" transform="rotate(-24 18.6 25.4)" fill="url(#cowsecHead)" stroke="#94a3b8" strokeWidth="0.5" />
      <ellipse cx="18.9" cy="25.3" rx="2.4" ry="1.15" transform="rotate(-24 18.9 25.3)" fill="#f9a8d4" />
      <ellipse cx="45.4" cy="25.4" rx="4.2" ry="2.4" transform="rotate(24 45.4 25.4)" fill="url(#cowsecHead)" stroke="#94a3b8" strokeWidth="0.5" />
      <ellipse cx="45.1" cy="25.3" rx="2.4" ry="1.15" transform="rotate(24 45.1 25.3)" fill="#f9a8d4" />

      {/* Head */}
      <path d="M32 18.2C39.8 18.2 43.4 23.4 43.4 30.4C43.4 34.4 42.2 37.4 40.6 39.6L23.4 39.6C21.8 37.4 20.6 34.4 20.6 30.4C20.6 23.4 24.2 18.2 32 18.2Z" fill="url(#cowsecHead)" />
      {/* Spots */}
      <path d="M24.2 22.4C26.4 21.2 28.6 22 28.8 24C29 26 27 27.4 25.2 26.8C23.8 26.3 22.9 23.9 24.2 22.4Z" fill="#0f172a" />
      <path d="M38.6 22C40.8 22.6 41.9 25 40.9 26.6C40 28 38 27.9 37.2 26.6C36.4 25.2 37.1 22.3 38.6 22Z" fill="#0f172a" />
      {/* Forelock tuft */}
      <path d="M29.2 18.9C30.2 17.2 31.4 16.9 32.3 18.3C33.1 16.8 34.6 17.1 35.1 18.9C33.9 19.6 30.6 19.7 29.2 18.9Z" fill="#0f172a" />

      {/* Eyes */}
      <ellipse cx="27.6" cy="29.6" rx="1.9" ry="2.3" fill="#0f172a" />
      <ellipse cx="36.4" cy="29.6" rx="1.9" ry="2.3" fill="#0f172a" />
      <circle cx="28.2" cy="28.7" r="0.75" fill="#ffffff" />
      <circle cx="37" cy="28.7" r="0.75" fill="#ffffff" />
      {/* Determined brows (on duty) */}
      <path d="M25.6 26.2L29.4 26.9" stroke="#0f172a" strokeWidth="0.9" strokeLinecap="round" />
      <path d="M38.4 26.2L34.6 26.9" stroke="#0f172a" strokeWidth="0.9" strokeLinecap="round" />

      {/* Muzzle */}
      <ellipse cx="32" cy="41" rx="9.6" ry="6.4" fill="url(#cowsecMuzzle)" stroke="#db2777" strokeOpacity="0.45" strokeWidth="0.6" />
      <ellipse cx="28.6" cy="40.4" rx="1.4" ry="1.9" fill="#831843" />
      <ellipse cx="35.4" cy="40.4" rx="1.4" ry="1.9" fill="#831843" />
      <path d="M29.6 44.2C31 45.2 33 45.2 34.4 44.2" stroke="#831843" strokeWidth="0.8" strokeLinecap="round" />

      {/* Collar tag: a tiny check, "all clear" */}
      <circle cx="32" cy="50.6" r="2.6" fill="#10b981" stroke="#ecfdf5" strokeWidth="0.6" />
      <path d="M30.8 50.6L31.7 51.5L33.3 49.8" stroke="#ecfdf5" strokeWidth="0.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
