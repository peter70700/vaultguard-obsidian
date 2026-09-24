/** Transport failures the AWS SDK itself declares retryable: throttling, a 429, a 5xx
 * from S3, KMS or DynamoDB, or a socket timeout/network failure code. They are recognised
 * POSITIVELY, by the SDK's own contract fields, so an unknown exception is still permanent
 * by construction.
 *
 * An owner that has to translate such a failure into its own typed error after proving
 * its write did not land (the collaboration store's `storage_unavailable`) may keep the
 * transport failure as the typed error's `cause`; the classification follows that
 * standard `cause` chain a bounded number of links. Only a cause that is itself one of
 * these SDK failures is ever attached, so the chain never carries request bytes.
 *
 * The publication service consults this only for a failure raised before any publication
 * transaction was dispatched, where the head compare-and-swap proves nothing was
 * published, and for a conflict derivation that could not be completed. */
const TRANSIENT_STORAGE_FAILURES: ReadonlySet<string> = new Set([
  "AbortError",
  "EC2ThrottledException",
  "InternalError",
  "InternalFailure",
  "InternalServerError",
  "KMSInternalException",
  "KMSThrottlingException",
  "LimitExceededException",
  "NetworkingError",
  "PriorRequestNotComplete",
  "ProvisionedThroughputExceededException",
  "RequestLimitExceeded",
  "RequestThrottled",
  "RequestThrottledException",
  "RequestTimeout",
  "RequestTimeoutException",
  "ServiceUnavailable",
  "SlowDown",
  "ThrottledException",
  "Throttling",
  "ThrottlingException",
  "TimeoutError",
  "TooManyRequestsException",
  "TransactionInProgressException",
]);
/** Node.js socket failure codes the SDK's own retry classification treats as transient
 * (`@smithy/service-error-classification`: timeout and network error codes). */
const TRANSIENT_NODE_ERROR_CODES: ReadonlySet<string> = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "EPIPE",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOTFOUND",
]);
/** How many `cause` links the classification follows. */
const MAX_CAUSE_DEPTH = 4;

export function isTransientStorageFailure(error: unknown, depth = 0): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as {
    name?: unknown;
    Code?: unknown;
    code?: unknown;
    cause?: unknown;
    $retryable?: { throttling?: unknown } | null;
    $metadata?: { httpStatusCode?: unknown } | null;
  };
  if (candidate.$retryable?.throttling === true) return true;
  const status = candidate.$metadata?.httpStatusCode;
  if (typeof status === "number" && (status === 429 || (status >= 500 && status <= 599))) return true;
  if (
    (typeof candidate.name === "string" && TRANSIENT_STORAGE_FAILURES.has(candidate.name)) ||
    (typeof candidate.Code === "string" && TRANSIENT_STORAGE_FAILURES.has(candidate.Code)) ||
    (typeof candidate.code === "string" && TRANSIENT_NODE_ERROR_CODES.has(candidate.code))
  )
    return true;
  return depth < MAX_CAUSE_DEPTH && candidate.cause !== undefined && isTransientStorageFailure(candidate.cause, depth + 1);
}

/** `typed` with the transport failure behind it kept as its `cause`, but only when that
 * failure is transient; any other failure is not attached. */
export function withTransientCause<T extends Error>(typed: T, failure: unknown): T {
  return isTransientStorageFailure(failure) ? Object.assign(typed, { cause: failure }) : typed;
}
