/**
 * VaultGuard — Security Metrics Emitter (SD-09-F1)
 *
 * Publishes the custom CloudWatch metrics that back the SNS security alarms in
 * `terraform/modules/monitoring/main.tf`. Before this module existed those
 * alarms were dead: nothing published their metrics, and every alarm sets
 * `treat_missing_data = "notBreaching"`, so a brute-force / exfil /
 * revoked-session / KMS-failure spike would never page an operator (SD-09-F1).
 *
 * Contract (mirrors `logAudit`'s "never block the operation" rule in
 * shared/utils.ts):
 *  - NEVER throws. A metrics failure must never regress the request it rides
 *    alongside.
 *  - Returns a Promise that never rejects, so a caller MAY `await` it for
 *    reliability (rare/critical paths, e.g. RevokedSessionAccess whose alarm
 *    fires at >= 1) or `void` it fire-and-forget on hot paths (FileAccessCount
 *    on every read) to avoid adding PutMetricData latency to the response.
 *  - No-op when `STAGE` is unset (unit tests / local) — never attempts a real
 *    PutMetricData there and never constructs a client (lazy).
 *  - Namespace + dimension are hard-pinned to what the alarms expect:
 *    namespace `ObsidianVaultGuard`, dimension `{ Stage: <stage> }`,
 *    `Unit: Count` so the alarms' `statistic = "Sum"` counts events.
 */

import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

const REGION = process.env.AWS_REGION || 'eu-west-1';

// Matches every alarm's `namespace` in terraform/modules/monitoring/main.tf.
// Changing this string silently dead-alarms all five metrics — change the
// Terraform in lockstep or not at all.
export const SECURITY_METRIC_NAMESPACE = 'ObsidianVaultGuard';

/**
 * The five custom security metrics. Each name MUST equal the `metric_name` of
 * its `aws_cloudwatch_metric_alarm` in terraform/modules/monitoring/main.tf,
 * or that alarm stays dead. Adding a name here without an alarm (or vice-versa)
 * is a silent no-op.
 */
export type SecurityMetricName =
  | 'FailedAuthentication'
  | 'FileAccessCount'
  | 'OffHoursPermissionChange'
  | 'RevokedSessionAccess'
  | 'KMSDecryptFailure';

// Lazy so merely importing this module (e.g. in unit tests, or in a handler on
// a code path that never emits) constructs no client and touches no network.
let cwClient: CloudWatchClient | null = null;
function getClient(): CloudWatchClient {
  if (!cwClient) {
    cwClient = new CloudWatchClient({ region: REGION });
  }
  return cwClient;
}

/**
 * Emit one data point for a security metric (default value 1 = one event).
 *
 * Returns a Promise that NEVER rejects:
 *  - hot paths (e.g. FileAccessCount on every read) SHOULD `void` this so the
 *    response is never delayed by PutMetricData latency;
 *  - rare / critical paths (revoked-session access, KMS decrypt failure) MAY
 *    `await` it so the data point is reliably flushed before the Lambda
 *    execution environment freezes.
 */
export async function emitSecurityMetric(
  metricName: SecurityMetricName,
  value = 1
): Promise<void> {
  const stage = process.env.STAGE;
  // No stage wired up (unit tests / local) → never touch CloudWatch.
  if (!stage) {
    return;
  }

  try {
    await getClient().send(
      new PutMetricDataCommand({
        Namespace: SECURITY_METRIC_NAMESPACE,
        MetricData: [
          {
            MetricName: metricName,
            Value: value,
            Unit: 'Count',
            Timestamp: new Date(),
            Dimensions: [{ Name: 'Stage', Value: stage }],
          },
        ],
      })
    );
  } catch (err) {
    // Never rethrow — a metrics failure must not break the request or the
    // audit write it rides alongside. Mirrors logAudit's [AUDIT_LOG_FAILURE].
    console.error('[SECURITY_METRIC_EMIT_FAILURE]', metricName, (err as Error).message);
  }
}
