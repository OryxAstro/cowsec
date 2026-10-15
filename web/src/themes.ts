export type ThemePalette = 'midnight' | 'alpine' | 'twilight' | 'clover' | 'harvest' | 'milkyway' | 'strawberry' | 'mint' | 'lavender' | 'buttercup';

export interface ThemePaletteConfig {
  id: ThemePalette;
  name: string;
  tagline: string;
  previewColors: [string, string, string]; // [bg, accent, highlight]
  previewGradient: string;
  mode?: 'light' | 'dark';
}

export const THEME_PALETTES: ThemePaletteConfig[] = [
  {
    id: 'midnight',
    name: 'Midnight Pasture',
    tagline: 'Dark · obsidian night and periwinkle',
    previewColors: ['#080d1a', '#818cf8', '#c084fc'],
    previewGradient: 'from-indigo-500 via-purple-400 to-pink-300',
  },
  {
    id: 'alpine',
    name: 'Alpine Dairy',
    tagline: 'Dark · arctic charcoal and glacier cyan',
    previewColors: ['#061017', '#38bdf8', '#5eead4'],
    previewGradient: 'from-sky-400 via-cyan-300 to-teal-200',
  },
  {
    id: 'twilight',
    name: 'Twilight Moo',
    tagline: 'Dark · midnight plum and orchid',
    previewColors: ['#0c0817', '#f472b6', '#c084fc'],
    previewGradient: 'from-pink-400 via-fuchsia-400 to-purple-300',
  },
  {
    id: 'clover',
    name: 'Clover Night',
    tagline: 'Dark · deep pine and clover green',
    previewColors: ['#05120d', '#34d399', '#6ee7b7'],
    previewGradient: 'from-emerald-400 via-teal-300 to-cyan-200',
  },
  {
    id: 'harvest',
    name: 'Harvest Barn',
    tagline: 'Dark · warm basalt, hay and terracotta',
    previewColors: ['#120c08', '#fb923c', '#fdba74'],
    previewGradient: 'from-amber-400 via-orange-400 to-rose-300',
  },
  {
    id: 'milkyway',
    name: 'Milky Way',
    tagline: 'Dark · graphite and starlit mauve',
    previewColors: ['#080d17', '#93c5fd', '#c4b5fd'],
    previewGradient: 'from-blue-400 via-indigo-300 to-purple-200',
  },
  {
    id: 'strawberry',
    name: 'Strawberry Milk',
    tagline: 'Light · blush pink and rose',
    previewColors: ['#fdf3f6', '#ec4899', '#f9a8d4'],
    previewGradient: 'from-pink-300 via-rose-200 to-pink-100',
    mode: 'light',
  },
  {
    id: 'mint',
    name: 'Mint Meadow',
    tagline: 'Light · fresh mint and clover',
    previewColors: ['#effaf5', '#10b981', '#99f6e4'],
    previewGradient: 'from-emerald-300 via-teal-200 to-cyan-100',
    mode: 'light',
  },
  {
    id: 'lavender',
    name: 'Lavender Field',
    tagline: 'Light · soft lilac and orchid',
    previewColors: ['#f5f3ff', '#8b5cf6', '#ddd6fe'],
    previewGradient: 'from-violet-300 via-purple-200 to-fuchsia-100',
    mode: 'light',
  },
  {
    id: 'buttercup',
    name: 'Buttercup Sky',
    tagline: 'Light · butter yellow and sky blue',
    previewColors: ['#fffbeb', '#0ea5e9', '#fde68a'],
    previewGradient: 'from-amber-200 via-yellow-100 to-sky-200',
    mode: 'light',
  },
];
