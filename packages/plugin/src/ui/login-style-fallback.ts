const LOGIN_STYLES_READY_PROPERTY = "--vaultguard-login-styles-ready";

type CssStyleMap = Partial<CSSStyleDeclaration>;

interface StyleableElement extends HTMLElement {
  setCssStyles(styles: CssStyleMap): void;
}

interface LoginStyleWindow {
  innerWidth: number;
  getComputedStyle(element: Element): CSSStyleDeclaration;
}

const MODAL_FALLBACK_STYLES: CssStyleMap = {
  width: "420px",
  maxWidth: "calc(100vw - 32px)",
  maxHeight: "calc(100vh - 48px)",
  display: "flex",
  flexDirection: "column",
  padding: "0",
  margin: "0",
};

const CONTENT_FALLBACK_STYLES: CssStyleMap = {
  width: "100%",
  maxWidth: "100%",
  maxHeight: "calc(100vh - 64px)",
  display: "flex",
  flexDirection: "column",
  boxSizing: "border-box",
  margin: "0",
  padding: "32px 28px 24px",
  overflowX: "hidden",
  overflowY: "auto",
};

const DESCENDANT_FALLBACK_STYLES: ReadonlyArray<
  readonly [selector: string, styles: CssStyleMap]
> = [
  [
    ".vaultguard-login-icon",
    {
      display: "flex",
      justifyContent: "center",
      marginBottom: "12px",
      color: "var(--interactive-accent)",
      lineHeight: "1",
    },
  ],
  [
    ".vaultguard-login-title",
    {
      textAlign: "center",
      margin: "0 0 4px",
      fontSize: "1.35em",
      fontWeight: "700",
      lineHeight: "1.25",
    },
  ],
  [
    ".vaultguard-login-subtitle",
    {
      textAlign: "center",
      margin: "0 0 24px",
      fontSize: "0.88em",
      lineHeight: "1.4",
      color: "var(--text-muted)",
    },
  ],
  [
    ".vaultguard-login-form",
    {
      display: "flex",
      flexDirection: "column",
      gap: "16px",
      minWidth: "0",
    },
  ],
  [
    ".vaultguard-field-group",
    {
      display: "flex",
      flexDirection: "column",
      gap: "5px",
    },
  ],
  [
    ".vaultguard-field-input",
    {
      width: "100%",
      minHeight: "38px",
      padding: "9px 12px",
      boxSizing: "border-box",
    },
  ],
  [
    ".vaultguard-password-wrap",
    {
      position: "relative",
      display: "flex",
      alignItems: "center",
    },
  ],
  [
    ".vaultguard-password-input",
    {
      paddingRight: "40px",
    },
  ],
  [
    ".vaultguard-password-toggle",
    {
      position: "absolute",
      right: "6px",
      top: "50%",
      transform: "translateY(-50%)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      width: "28px",
      height: "28px",
      padding: "0",
      border: "none",
      borderRadius: "4px",
      background: "transparent",
      color: "var(--text-muted)",
    },
  ],
  [
    ".vaultguard-forgot-link",
    {
      textAlign: "right",
      marginTop: "-8px",
    },
  ],
  [
    ".vaultguard-login-actions",
    {
      display: "flex",
      gap: "10px",
      marginTop: "24px",
      paddingTop: "18px",
      borderTop: "1px solid var(--background-modifier-border)",
      flexShrink: "0",
    },
  ],
  [
    ".vaultguard-login-actions button",
    {
      flex: "1",
      minWidth: "0",
      minHeight: "36px",
      padding: "8px 16px",
      whiteSpace: "nowrap",
    },
  ],
  [
    ".vaultguard-login-footer",
    {
      marginTop: "14px",
      textAlign: "center",
    },
  ],
];

/**
 * Apply a minimal login layout only when Obsidian did not attach the plugin's
 * shipped styles.css. The normal path remains class-based CSS; this recovery
 * path deliberately uses Obsidian's setCssStyles helper instead of injecting a
 * runtime stylesheet, which is disallowed by the community-plugin review.
 */
export function applyLoginStyleFallbackIfNeeded(
  modalEl: StyleableElement,
  contentEl: StyleableElement
): boolean {
  const styleWindow = contentEl.ownerDocument?.defaultView as LoginStyleWindow | null;
  const stylesReady = styleWindow
    ?.getComputedStyle(contentEl)
    .getPropertyValue(LOGIN_STYLES_READY_PROPERTY)
    .trim();

  if (stylesReady === "1") {
    return false;
  }

  modalEl.setCssStyles(MODAL_FALLBACK_STYLES);
  contentEl.setCssStyles({
    ...CONTENT_FALLBACK_STYLES,
    ...(styleWindow && styleWindow.innerWidth <= 420
      ? { padding: "28px 20px 20px" }
      : {}),
  });

  for (const [selector, styles] of DESCENDANT_FALLBACK_STYLES) {
    contentEl.querySelectorAll<StyleableElement>(selector).forEach((element) => {
      element.setCssStyles(styles);
    });
  }

  if (styleWindow && styleWindow.innerWidth <= 420) {
    contentEl
      .querySelectorAll<StyleableElement>(".vaultguard-login-actions")
      .forEach((actions) => {
        actions.setCssStyles({ flexDirection: "column-reverse" });
      });
    contentEl
      .querySelectorAll<StyleableElement>(".vaultguard-login-actions button")
      .forEach((button) => {
        button.setCssStyles({ width: "100%" });
      });
  }

  return true;
}

/** Clear root inline recovery styles if a Modal instance is reused. */
export function clearLoginStyleFallback(
  modalEl: StyleableElement,
  contentEl: StyleableElement
): void {
  modalEl.setCssStyles(clearStyles(MODAL_FALLBACK_STYLES));
  contentEl.setCssStyles(clearStyles(CONTENT_FALLBACK_STYLES));
}

function clearStyles(styles: CssStyleMap): CssStyleMap {
  return Object.fromEntries(Object.keys(styles).map((property) => [property, ""]));
}

export const __TEST_LOGIN_STYLES_READY_PROPERTY = LOGIN_STYLES_READY_PROPERTY;
