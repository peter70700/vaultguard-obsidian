const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl<K extends keyof SVGElementTagNameMap>(
  tag: K,
  attrs: Record<string, string>
): SVGElementTagNameMap[K] {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) {
    el.setAttribute(name, value);
  }
  return el;
}

/**
 * The VaultGuard mark at modal size — the approved Mineral Governance folded
 * shield, geometry copied verbatim from
 * `landing/public/brand/logo/vaultguard-mark.svg`. Do not redraw it.
 *
 * Rendered at 48px by `.vaultguard-login-icon svg` and
 * `.vaultguard-pin-modal-icon svg`, which is above the 44px floor share-bridge
 * measured for the folded layers, so this keeps the canonical outer edge — the
 * ribbon mark (`VAULTGUARD_ICON`) drops it because 18px cannot hold it.
 *
 * Two deliberate departures from the canonical asset, both because this renders
 * in ONE colour where the asset uses three:
 *  - The spine is dropped. In the asset it is verdigris over a brass fold; at a
 *    single colour it crosses the lock plate and reads as an artifact.
 *  - The lock is solid rather than an outlined plate with a boss, matching the
 *    ribbon mark so the two stay one family.
 * Strokes are the canonical weights at x1.6, which a rendered size matrix put at
 * the point where the outer edge still reads as a finer contour than the fold it
 * frames instead of a third competing ring.
 *
 * Monochrome `currentColor` on purpose — both call sites set
 * `color: var(--interactive-accent)`, so the mark follows the user's theme. The
 * brand's brass and verdigris are NOT applied here; they are drawn for the
 * landing's warm paper and would fight an arbitrary theme.
 */
export function createShieldIcon(parent: HTMLElement): SVGSVGElement {
  const svg = svgEl("svg", {
    xmlns: SVG_NS,
    width: "48",
    height: "48",
    viewBox: "0 0 96 96",
    fill: "none",
    stroke: "currentColor",
    "stroke-linejoin": "round",
  });
  // outer edge → ward → keep, then the lock
  svg.appendChild(
    svgEl("path", {
      d: "M48 4 87 19v28c0 23-15 38-39 47C24 85 9 70 9 47V19L48 4Z",
      "stroke-width": "2.24",
    })
  );
  svg.appendChild(
    svgEl("path", {
      d: "M48 11 80 23v23c0 20-12 33-32 42-20-9-32-22-32-42V23l32-12Z",
      "stroke-width": "3.52",
    })
  );
  svg.appendChild(
    svgEl("path", {
      d: "M48 26 65 34v15c0 11-6 19-17 25-11-6-17-14-17-25V34l17-8Z",
      "stroke-width": "2.72",
    })
  );
  svg.appendChild(
    svgEl("rect", {
      x: "42",
      y: "41",
      width: "12",
      height: "12",
      rx: "2",
      fill: "currentColor",
      stroke: "none",
    })
  );
  parent.appendChild(svg);
  return svg;
}

export interface QrModuleProvider {
  getModuleCount(): number;
  isDark(row: number, col: number): boolean;
}

export function createQrSvg(
  parent: HTMLElement,
  qr: QrModuleProvider,
  options: { cellSize: number; margin: number; cssClass?: string }
): SVGSVGElement {
  const count = qr.getModuleCount();
  const size = (count + options.margin * 2) * options.cellSize;
  const svg = svgEl("svg", {
    xmlns: SVG_NS,
    viewBox: `0 0 ${size} ${size}`,
    "shape-rendering": "crispEdges",
    width: "200",
    height: "200",
  });
  if (options.cssClass) svg.classList.add(options.cssClass);

  svg.appendChild(
    svgEl("rect", {
      x: "0",
      y: "0",
      width: String(size),
      height: String(size),
      fill: "#ffffff",
    })
  );

  let path = "";
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (!qr.isDark(row, col)) continue;
      const x = (col + options.margin) * options.cellSize;
      const y = (row + options.margin) * options.cellSize;
      path += `M${x},${y}h${options.cellSize}v${options.cellSize}h-${options.cellSize}z`;
    }
  }
  svg.appendChild(svgEl("path", { d: path, fill: "#000000" }));

  parent.appendChild(svg);
  return svg;
}
