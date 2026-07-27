export interface NamedCleanupTask {
  name: string;
  promise: Promise<unknown>;
}

export interface CleanupSummary {
  fulfilled: string[];
  rejected: string[];
  timedOut: string[];
}

type CleanupStatus = "pending" | "fulfilled" | "rejected";

/**
 * Observe already-started cleanup work under one shared deadline. Every task
 * receives a rejection handler immediately, including work that settles after
 * the caller's deadline, so ignored cancellation never becomes an unhandled
 * rejection. The returned names must be non-sensitive operation classes.
 */
export async function settleCleanupTasks(
  tasks: readonly NamedCleanupTask[],
  timeoutMs: number,
): Promise<CleanupSummary> {
  if (tasks.length === 0) {
    return { fulfilled: [], rejected: [], timedOut: [] };
  }

  const statuses: CleanupStatus[] = tasks.map(() => "pending");
  const observers = tasks.map((task, index) =>
    Promise.resolve(task.promise).then(
      () => {
        statuses[index] = "fulfilled";
      },
      () => {
        statuses[index] = "rejected";
      },
    ),
  );

  let timer: ReturnType<typeof setTimeout> | null = null;
  await Promise.race([
    Promise.all(observers),
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, Math.max(0, timeoutMs));
    }),
  ]);
  if (timer !== null) clearTimeout(timer);

  const summary: CleanupSummary = { fulfilled: [], rejected: [], timedOut: [] };
  tasks.forEach((task, index) => {
    const status = statuses[index];
    if (status === "fulfilled") summary.fulfilled.push(task.name);
    else if (status === "rejected") summary.rejected.push(task.name);
    else summary.timedOut.push(task.name);
  });
  return summary;
}
