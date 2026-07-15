export type PermissionsGraphOverviewTheme = "light" | "dark";

export interface PermissionsGraphOverviewPalette {
  readonly theme: PermissionsGraphOverviewTheme;
  readonly background: string;
  readonly unknown: string;
  readonly file: string;
  readonly folder: string;
  readonly user: string;
  readonly group: string;
  readonly vault: string;
  readonly aggregate: string;
  readonly outline: string;
  readonly materialized: string;
  readonly selected: string;
}

const LIGHT_PALETTE: PermissionsGraphOverviewPalette = Object.freeze({
  theme: "light",
  background: "#ffffff",
  unknown: "#374151",
  file: "#1d4ed8",
  folder: "#92400e",
  user: "#6d28d9",
  group: "#0f766e",
  vault: "#9f1239",
  aggregate: "#334155",
  outline: "#ffffff",
  materialized: "#111827",
  selected: "#0369a1",
});

const DARK_PALETTE: PermissionsGraphOverviewPalette = Object.freeze({
  theme: "dark",
  background: "#1e1e1e",
  unknown: "#d1d5db",
  file: "#60a5fa",
  folder: "#fbbf24",
  user: "#c4b5fd",
  group: "#5eead4",
  vault: "#fda4af",
  aggregate: "#cbd5e1",
  outline: "#111827",
  materialized: "#f9fafb",
  selected: "#38bdf8",
});

export function getPermissionsGraphOverviewPalette(
  theme: PermissionsGraphOverviewTheme,
): PermissionsGraphOverviewPalette {
  return theme === "dark" ? DARK_PALETTE : LIGHT_PALETTE;
}

export function permissionsGraphOverviewContrastRatio(
  foreground: string,
  background: string,
): number {
  const first = relativeLuminance(parseHexColor(foreground));
  const second = relativeLuminance(parseHexColor(background));
  const lighter = Math.max(first, second);
  const darker = Math.min(first, second);
  return (lighter + 0.05) / (darker + 0.05);
}

function parseHexColor(value: string): readonly [number, number, number] {
  if (!/^#[0-9a-f]{6}$/i.test(value)) throw new Error("Overview palette colors must use six-digit hex values.");
  return Object.freeze([
    Number.parseInt(value.slice(1, 3), 16),
    Number.parseInt(value.slice(3, 5), 16),
    Number.parseInt(value.slice(5, 7), 16),
  ] as const);
}

function relativeLuminance(rgb: readonly [number, number, number]): number {
  const channels = rgb.map((value) => {
    const normalized = value / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return (channels[0] ?? 0) * 0.2126 + (channels[1] ?? 0) * 0.7152 + (channels[2] ?? 0) * 0.0722;
}
