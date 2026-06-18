/**
 * Vitest setup — provides global mocks for Obsidian APIs and Web Crypto.
 *
 * Node 18+ ships Web Crypto on globalThis.crypto, so AES-GCM, HKDF,
 * PBKDF2, etc. all work natively without polyfills.
 */

import { vi } from 'vitest';

// ── Mock Obsidian module ──────────────────────────────────────────────────────
// Only the APIs the source code actually imports need stubs.
class MockComponent {
  constructor(public inputEl: Record<string, unknown> = {}) {}

  setButtonText(): this {
    return this;
  }

  setCta(): this {
    return this;
  }

  setWarning(): this {
    return this;
  }

  setDisabled(): this {
    return this;
  }

  setPlaceholder(): this {
    return this;
  }

  setValue(): this {
    return this;
  }

  setTooltip(): this {
    return this;
  }

  setIcon(): this {
    return this;
  }

  setClass(): this {
    return this;
  }

  onClick(): this {
    return this;
  }

  onChange(): this {
    return this;
  }

  addOption(): this {
    return this;
  }
}

class MockButtonComponent extends MockComponent {}
class MockTextComponent extends MockComponent {}
class MockDropdownComponent extends MockComponent {}

class MockModal {
  app: unknown;
  contentEl = {};
  modalEl = {};

  constructor(app?: unknown) {
    this.app = app;
  }

  open(): void {}

  close(): void {}
}

class MockPlugin {
  app: unknown;

  constructor(app?: unknown) {
    this.app = app;
  }

  addSettingTab(): void {}
  addRibbonIcon(): void {}
  addStatusBarItem(): HTMLElement | null {
    return null;
  }
  addCommand(): void {}
  registerView(): void {}
  registerInterval(): void {}
  registerEvent(): void {}
  registerDomEvent(): void {}
  registerExtensions(): void {}
  registerMarkdownCodeBlockProcessor(): void {}
  async loadData(): Promise<Record<string, unknown>> {
    return {};
  }
  async saveData(): Promise<void> {}
}

class MockPluginSettingTab {
  app: unknown;
  plugin: unknown;
  containerEl = {
    empty: vi.fn(),
    createEl: vi.fn(() => ({})),
    createDiv: vi.fn(() => ({})),
    querySelector: vi.fn(() => null),
  };

  constructor(app: unknown, plugin: unknown) {
    this.app = app;
    this.plugin = plugin;
  }
}

class MockSetting {
  constructor(_containerEl?: unknown) {}

  setName(): this {
    return this;
  }

  setDesc(): this {
    return this;
  }

  setHeading(): this {
    return this;
  }

  setDisabled(): this {
    return this;
  }

  clear(): this {
    return this;
  }

  addButton(cb: (button: MockButtonComponent) => void): this {
    cb(new MockButtonComponent());
    return this;
  }

  addText(cb: (text: MockTextComponent) => void): this {
    cb(new MockTextComponent());
    return this;
  }

  addDropdown(cb: (dropdown: MockDropdownComponent) => void): this {
    cb(new MockDropdownComponent());
    return this;
  }

  addToggle(cb: (toggle: MockComponent) => void): this {
    cb(new MockComponent());
    return this;
  }

  addSlider(cb: (slider: MockComponent) => void): this {
    cb(new MockComponent());
    return this;
  }
}

class MockItemView {
  leaf: unknown;
  containerEl = { children: [{ empty: vi.fn(), createDiv: vi.fn(() => ({})) }] };

  constructor(leaf?: unknown) {
    this.leaf = leaf;
  }
}

class MockMarkdownView {}
class MockWorkspaceLeaf {}
class MockApp {}
class MockTAbstractFile {
  path = '';
}
class MockTFile extends MockTAbstractFile {}
class MockTFolder extends MockTAbstractFile {}
class MockMenuItem {
  title: string | DocumentFragment = '';
  icon: string | null = null;
  disabled = false;
  checked: boolean | null = null;
  warning = false;
  isLabel = false;
  section = '';
  clickHandler: ((evt: MouseEvent | KeyboardEvent) => unknown) | null = null;

  setTitle(title: string | DocumentFragment): this {
    this.title = title;
    return this;
  }

  setIcon(icon: string | null): this {
    this.icon = icon;
    return this;
  }

  setDisabled(disabled: boolean): this {
    this.disabled = disabled;
    return this;
  }

  setChecked(checked: boolean | null): this {
    this.checked = checked;
    return this;
  }

  setWarning(isWarning: boolean): this {
    this.warning = isWarning;
    return this;
  }

  setIsLabel(isLabel: boolean): this {
    this.isLabel = isLabel;
    return this;
  }

  setSection(section: string): this {
    this.section = section;
    return this;
  }

  onClick(callback: (evt: MouseEvent | KeyboardEvent) => unknown): this {
    this.clickHandler = callback;
    return this;
  }
}

class MockMenu {
  static instances: MockMenu[] = [];
  items: MockMenuItem[] = [];
  separators = 0;
  showAtMouseEvent = vi.fn(() => this);
  showAtPosition = vi.fn(() => this);
  hide = vi.fn(() => this);
  close = vi.fn();
  onHide = vi.fn();

  constructor() {
    MockMenu.instances.push(this);
  }

  addItem(cb: (item: MockMenuItem) => unknown): this {
    const item = new MockMenuItem();
    this.items.push(item);
    cb(item);
    return this;
  }

  addSeparator(): this {
    this.separators += 1;
    return this;
  }

  setNoIcon(): this {
    return this;
  }

  setUseNativeMenu(): this {
    return this;
  }
}

// Mutable Platform flag — individual tests can flip `Platform.isMobileApp`
// via `Object.assign(Platform, { isMobileApp: true })` to exercise the
// mobile code paths. Defaults to desktop so the existing suite is unaffected.
const Platform = {
  isMobile: false,
  isMobileApp: false,
  isDesktop: true,
  isDesktopApp: true,
  isIosApp: false,
  isAndroidApp: false,
  isPhone: false,
  isTablet: false,
  isMacOS: true,
  isWin: false,
  isLinux: false,
  isSafari: false,
};

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: MockPlugin,
  Platform,
  App: MockApp,
  Modal: MockModal,
  PluginSettingTab: MockPluginSettingTab,
  Setting: MockSetting,
  ButtonComponent: MockButtonComponent,
  DropdownComponent: MockDropdownComponent,
  TextComponent: MockTextComponent,
  ItemView: MockItemView,
  MarkdownView: MockMarkdownView,
  WorkspaceLeaf: MockWorkspaceLeaf,
  TFile: MockTFile,
  TFolder: MockTFolder,
  TAbstractFile: MockTAbstractFile,
  Menu: MockMenu,
  normalizePath: (p: string) => p,
  addIcon: vi.fn(),
  setIcon: vi.fn(),
  // ── Events ─────────────────────────────────────────────────────────────────
  // Required so `class PermissionStore extends Events` instantiates under
  // vi.mock('obsidian'). The stub actually dispatches listeners synchronously
  // through `trigger(name, ...args)` so fan-out spy tests can assert that
  // emitting fires registered handlers.
  Events: class {
    private listeners = new Map<string, Array<(...args: unknown[]) => unknown>>();
    on(name: string, cb: (...args: unknown[]) => unknown) {
      const arr = this.listeners.get(name) ?? [];
      arr.push(cb);
      this.listeners.set(name, arr);
      return { name, cb };
    }
    off(name: string, cb: (...args: unknown[]) => unknown) {
      const arr = this.listeners.get(name) ?? [];
      this.listeners.set(name, arr.filter((x) => x !== cb));
    }
    offref(ref: { name: string; cb: (...args: unknown[]) => unknown }) {
      if (ref && typeof ref === "object" && "name" in ref && "cb" in ref) {
        this.off(ref.name as string, ref.cb as (...args: unknown[]) => unknown);
      }
    }
    trigger(name: string, ...args: unknown[]) {
      for (const cb of this.listeners.get(name) ?? []) cb(...args);
    }
    tryTrigger() {}
  },
}));
