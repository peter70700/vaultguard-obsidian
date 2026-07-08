import { Modal, setIcon, type App } from "obsidian";
import {
  formatBytes,
  formatDuration,
  type LongOperationManager,
  type LongOperationProgressSnapshot,
} from "../plugin/long-operation";

function emptyEl(el: HTMLElement): void {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

function appendText(parent: HTMLElement, className: string, text: string): HTMLElement {
  const el = parent.ownerDocument.createElement("span");
  el.className = className;
  el.textContent = text;
  parent.appendChild(el);
  return el;
}

function appendDiv(parent: HTMLElement, className: string): HTMLDivElement {
  const el = parent.ownerDocument.createElement("div");
  el.className = className;
  parent.appendChild(el);
  return el;
}

function formatPercent(snapshot: LongOperationProgressSnapshot): string {
  if (snapshot.percent === null) return snapshot.approximatePercent ? "Approximate" : "Unknown";
  const suffix = snapshot.approximatePercent ? " approx" : "";
  return `${Math.round(snapshot.percent)}%${suffix}`;
}

function formatCount(snapshot: LongOperationProgressSnapshot): string {
  if (snapshot.totalItems === null) {
    return `${snapshot.processedItems.toLocaleString()} processed`;
  }
  return `${snapshot.processedItems.toLocaleString()} of ${snapshot.totalItems.toLocaleString()}`;
}

function formatThroughput(snapshot: LongOperationProgressSnapshot): string {
  if (snapshot.throughput.bytesPerSecond && snapshot.throughput.bytesPerSecond > 0) {
    return `${formatBytes(snapshot.throughput.bytesPerSecond)}/s`;
  }
  if (snapshot.throughput.itemsPerSecond && snapshot.throughput.itemsPerSecond > 0) {
    return `${snapshot.throughput.itemsPerSecond.toFixed(1)} items/s`;
  }
  return "calculating";
}

function describeState(snapshot: LongOperationProgressSnapshot): string {
  if (snapshot.lifecycleState === "failed") return "Failed";
  if (snapshot.lifecycleState === "completed") return "Complete";
  if (snapshot.lifecycleState === "cancelled") return "Cancelled";
  if (snapshot.lifecycleState === "paused") return "Paused";
  if (snapshot.stallState === "possibly-stalled") return "Possibly stuck";
  if (snapshot.stallState === "slow") return "Slow but progressing";
  return "Running";
}

function renderProgressBar(parent: HTMLElement, snapshot: LongOperationProgressSnapshot): void {
  const track = appendDiv(parent, "vaultguard-long-op-progress-track");
  const fill = appendDiv(track, "vaultguard-long-op-progress-fill");
  const percent = snapshot.percent ?? (snapshot.lifecycleState === "completed" ? 100 : null);
  fill.style.width = percent === null ? "100%" : `${Math.max(2, Math.min(100, percent))}%`;
  if (percent === null) {
    fill.addClass("is-indeterminate");
  }
}

export function renderLongOperationStatusBar(
  statusBarEl: HTMLElement,
  snapshot: LongOperationProgressSnapshot
): void {
  emptyEl(statusBarEl);
  statusBarEl.classList.add("vaultguard-long-op-statusbar");

  const icon = statusBarEl.ownerDocument.createElement("span");
  icon.className = "vaultguard-long-op-statusbar-icon";
  setIcon(icon, snapshot.lifecycleState === "completed" ? "check" : "shield");
  statusBarEl.appendChild(icon);

  const label = statusBarEl.ownerDocument.createElement("span");
  label.className = "vaultguard-long-op-statusbar-label";
  label.textContent = `VaultGuard ${formatPercent(snapshot)} ${snapshot.phase}`;
  statusBarEl.appendChild(label);

  const eta =
    snapshot.lifecycleState === "completed"
      ? "done"
      : `ETA ${formatDuration(snapshot.eta.remainingMs)}`;
  statusBarEl.setAttribute(
    "title",
    `${snapshot.operationName}: ${describeState(snapshot)}. ${formatCount(snapshot)}. ${eta}.`
  );
}

export class ProtectedLongOperationModal extends Modal {
  private snapshot: LongOperationProgressSnapshot | null = null;

  constructor(
    app: App,
    private readonly manager: LongOperationManager,
    snapshot: LongOperationProgressSnapshot
  ) {
    super(app);
    this.snapshot = snapshot;
  }

  onOpen(): void {
    this.modalEl.classList.add("vaultguard-long-operation-modal");
    this.render();
  }

  update(snapshot: LongOperationProgressSnapshot): void {
    this.snapshot = snapshot;
    this.render();
    if (
      snapshot.lifecycleState === "completed" ||
      snapshot.lifecycleState === "failed" ||
      snapshot.lifecycleState === "cancelled"
    ) {
      window.setTimeout(() => this.close(), 2500);
    }
  }

  private render(): void {
    if (!this.snapshot) return;
    const snapshot = this.snapshot;
    const root = this.contentEl;
    emptyEl(root);

    const shell = appendDiv(root, "vaultguard-long-op-shell");
    const header = appendDiv(shell, "vaultguard-long-op-header");
    const icon = appendDiv(header, "vaultguard-long-op-icon");
    setIcon(icon, "shield-check");
    const titleWrap = appendDiv(header, "vaultguard-long-op-title-wrap");
    const title = titleWrap.ownerDocument.createElement("h2");
    title.className = "vaultguard-long-op-title";
    title.textContent = snapshot.operationName;
    titleWrap.appendChild(title);
    appendText(titleWrap, "vaultguard-long-op-subtitle", describeState(snapshot));

    const phase = appendDiv(shell, "vaultguard-long-op-phase");
    appendText(phase, "vaultguard-long-op-phase-label", "Phase");
    appendText(phase, "vaultguard-long-op-phase-value", snapshot.phase);

    renderProgressBar(shell, snapshot);

    const grid = appendDiv(shell, "vaultguard-long-op-grid");
    this.renderMetric(grid, "Items", formatCount(snapshot));
    this.renderMetric(grid, "Bytes", this.formatBytes(snapshot));
    this.renderMetric(grid, "Progress", formatPercent(snapshot));
    this.renderMetric(grid, "Elapsed", formatDuration(snapshot.elapsedMs));
    this.renderMetric(grid, "ETA", formatDuration(snapshot.eta.remainingMs));
    this.renderMetric(grid, "Throughput", formatThroughput(snapshot));

    if (snapshot.warning) {
      const warning = appendDiv(shell, "vaultguard-long-op-warning");
      setIcon(warning, "triangle-alert");
      appendText(warning, "vaultguard-long-op-warning-text", snapshot.warning);
    }

    if (snapshot.stallState === "possibly-stalled" || snapshot.stallState === "slow") {
      const stalled = appendDiv(shell, "vaultguard-long-op-stall");
      setIcon(stalled, "clock-alert");
      appendText(
        stalled,
        "vaultguard-long-op-stall-text",
        snapshot.stallState === "possibly-stalled"
          ? "No progress has been reported recently. VaultGuard is still watching the operation."
          : "This operation is slower than usual but progress tracking is still active."
      );
    }

    if (snapshot.capabilities.protectedPhase) {
      const protectedPhase = appendDiv(shell, "vaultguard-long-op-protected");
      setIcon(protectedPhase, "lock");
      appendText(
        protectedPhase,
        "vaultguard-long-op-protected-text",
        "Protected phase. Pause and cancellation are unavailable until a safe checkpoint exists."
      );
    }

    if (snapshot.failureReason) {
      const failure = appendDiv(shell, "vaultguard-long-op-failure");
      setIcon(failure, "circle-alert");
      appendText(failure, "vaultguard-long-op-failure-text", snapshot.failureReason);
    } else if (snapshot.message) {
      appendText(shell, "vaultguard-long-op-message", snapshot.message);
    }

    this.renderControls(shell, snapshot);
  }

  private renderMetric(parent: HTMLElement, label: string, value: string): void {
    const metric = appendDiv(parent, "vaultguard-long-op-metric");
    appendText(metric, "vaultguard-long-op-metric-label", label);
    appendText(metric, "vaultguard-long-op-metric-value", value);
  }

  private formatBytes(snapshot: LongOperationProgressSnapshot): string {
    if (snapshot.totalBytes === null) {
      return snapshot.processedBytes > 0 ? formatBytes(snapshot.processedBytes) : "not measured";
    }
    return `${formatBytes(snapshot.processedBytes)} of ${formatBytes(snapshot.totalBytes)}`;
  }

  private renderControls(
    parent: HTMLElement,
    snapshot: LongOperationProgressSnapshot
  ): void {
    if (!snapshot.capabilities.canPause && !snapshot.capabilities.canCancel) return;
    const controls = appendDiv(parent, "vaultguard-long-op-controls");

    if (snapshot.capabilities.canPause) {
      const pause = controls.ownerDocument.createElement("button");
      pause.type = "button";
      pause.className = "mod-cta vaultguard-long-op-control";
      pause.textContent = snapshot.lifecycleState === "paused" ? "Resume" : "Pause";
      pause.addEventListener("click", () => {
        if (snapshot.lifecycleState === "paused") {
          this.manager.resume(snapshot.id);
        } else {
          this.manager.requestPause(snapshot.id);
        }
      });
      controls.appendChild(pause);
    }

    if (snapshot.capabilities.canCancel) {
      const cancel = controls.ownerDocument.createElement("button");
      cancel.type = "button";
      cancel.className = "mod-warning vaultguard-long-op-control";
      cancel.textContent = "Cancel at checkpoint";
      cancel.addEventListener("click", () => this.manager.requestCancel(snapshot.id));
      controls.appendChild(cancel);
    }
  }
}

export class LongOperationUiController {
  private unsubscribe: (() => void) | null = null;
  private readonly modals = new Map<string, ProtectedLongOperationModal>();

  constructor(
    private readonly app: App,
    private readonly manager: LongOperationManager
  ) {}

  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.manager.subscribe((snapshot, event) => {
      if (snapshot.placement !== "protected") return;
      if (event === "removed") {
        const modal = this.modals.get(snapshot.id);
        modal?.close();
        this.modals.delete(snapshot.id);
        return;
      }

      let modal = this.modals.get(snapshot.id);
      if (!modal) {
        modal = new ProtectedLongOperationModal(this.app, this.manager, snapshot);
        this.modals.set(snapshot.id, modal);
        modal.open();
        return;
      }
      modal.update(snapshot);
    });
  }

  destroy(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    for (const modal of this.modals.values()) {
      modal.close();
    }
    this.modals.clear();
  }
}
