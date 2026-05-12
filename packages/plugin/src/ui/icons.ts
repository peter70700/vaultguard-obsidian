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

export function createShieldIcon(parent: HTMLElement): SVGSVGElement {
  const svg = svgEl("svg", {
    xmlns: SVG_NS,
    width: "48",
    height: "48",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "1.5",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
  });
  svg.appendChild(
    svgEl("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" })
  );
  svg.appendChild(svgEl("path", { d: "m9 12 2 2 4-4" }));
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
