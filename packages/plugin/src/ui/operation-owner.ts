export interface OperationLease {
  readonly generation: number;
  isCurrent(): boolean;
}

/**
 * Small ownership primitive for async UI work. Starting a newer operation,
 * invalidating, or closing the owner makes every older lease stale. It does not
 * cancel the underlying promise; it controls who may commit UI state.
 */
export class OperationOwner {
  private generation = 0;
  private closed = true;

  get isClosed(): boolean {
    return this.closed;
  }

  activate(): void {
    this.closed = false;
    this.generation += 1;
  }

  begin(): OperationLease {
    if (this.closed) {
      throw new Error("Cannot start work for a closed operation owner.");
    }
    const generation = ++this.generation;
    return {
      generation,
      isCurrent: () => !this.closed && this.generation === generation,
    };
  }

  invalidate(): void {
    this.generation += 1;
  }

  close(): void {
    this.closed = true;
    this.generation += 1;
  }
}
