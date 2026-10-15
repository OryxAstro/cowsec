export type ThemePalette = 'indigo' | 'frost' | 'twilight' | 'grove' | 'sunset' | 'nebula';

export interface ThemePaletteConfig {
  id: ThemePalette;
  name: string;
  tagline: string;
  previewColors: [string, string, string]; // [bg, accent, highlight]
  previewGradient: string;
}

export const THEME_PALETTES: ThemePaletteConfig[] = [
  {
    id: 'indigo',
    name: 'Cyber Indigo',
    tagline: 'Obsidian Slate & Pastel Periwinkle',
    previewColors: ['#080d1a', '#818cf8', '#c084fc'],
    previewGradient: 'from-indigo-500 via-purple-400 to-pink-300',
  },
  {
    id: 'frost',
    name: 'Nordic Frost',
    tagline: 'Arctic Charcoal & Glacial Cyan',
    previewColors: ['#061017', '#38bdf8', '#5eead4'],
    previewGradient: 'from-sky-400 via-cyan-300 to-teal-200',
  },
  {
    id: 'twilight',
    name: 'Tokyo Twilight',
    tagline: 'Midnight Plum, Sakura & Orchid',
    previewColors: ['#0c0817', '#f472b6', '#c084fc'],
    previewGradient: 'from-pink-400 via-fuchsia-400 to-purple-300',
  },
  {
    id: 'grove',
    name: 'Emerald Grove',
    tagline: 'Deep Pine, Eucalyptus & Mint',
    previewColors: ['#05120d', '#34d399', '#6ee7b7'],
    previewGradient: 'from-emerald-400 via-teal-300 to-cyan-200',
  },
  {
    id: 'sunset',
    name: 'Sunset Amber',
    tagline: 'Warm Basalt, Peach & Terracotta',
    previewColors: ['#120c08', '#fb923c', '#fdba74'],
    previewGradient: 'from-amber-400 via-orange-400 to-rose-300',
  },
  {
    id: 'nebula',
    name: 'Nebula Mist',
    tagline: 'Titanium Graphite & Mauve Celestial',
    previewColors: ['#080d17', '#93c5fd', '#c4b5fd'],
    previewGradient: 'from-blue-400 via-indigo-300 to-purple-200',
  },
];
