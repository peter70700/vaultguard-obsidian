/**
 * VaultGuard — Email Lambda Handler
 *
 * Sends transactional emails via AWS SES for the VaultGuard Obsidian plugin SaaS.
 * Invoked internally by other Lambdas (not exposed via API Gateway).
 *
 * Supported email types:
 * - welcome            — Sent after org signup
 * - invitation         — Sent when admin invites a user
 * - password-reset     — Sent for forgot-password flow
 * - payment-success    — Receipt after payment
 * - payment-failed     — Alert on payment failure
 * - subscription-cancelled — Notice of cancellation
 *
 * Usage from another Lambda (in-process):
 *   import { sendEmail } from '../email/handler';
 *   await sendEmail('welcome', { email, orgName, orgSlug, adminName });
 *
 * Usage via Lambda invocation (JSON payload):
 *   { "type": "welcome", "params": { "email": "...", ... } }
 */

import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

// ─── Configuration ───────────────────────────────────────────────────────────

const SENDER_EMAIL = process.env.SENDER_EMAIL || 'noreply@example.com';
const SES_CONFIGURATION_SET = process.env.SES_CONFIGURATION_SET || '';
const REGION = process.env.AWS_REGION || 'eu-central-1';

const sesClient = new SESClient({ region: REGION });

// ─── Types ───────────────────────────────────────────────────────────────────

interface WelcomeParams {
  email: string;
  orgName: string;
  orgSlug: string;
  adminName: string;
}

interface InvitationParams {
  email: string;
  orgName: string;
  /** Org slug used by the plugin's auto-discovery (`/orgs/{slug}/config`). */
  orgSlug?: string;
  inviterName: string;
  username: string;
  adminPanelUrl?: string;
}

interface PasswordResetParams {
  email: string;
  resetCode: string;
  expiresInMinutes: number;
}

interface PaymentSuccessParams {
  email: string;
  orgName: string;
  amount: string;
  currency: string;
  invoiceDate: string;
  plan: string;
}

interface PaymentFailedParams {
  email: string;
  orgName: string;
  amount: string;
  currency: string;
  nextRetryDate: string;
  portalUrl: string;
}

interface SubscriptionCancelledParams {
  email: string;
  orgName: string;
  accessEndDate: string;
}

interface TrialActivationParams {
  email: string;
  orgName: string;
  adminName: string;
  /** Where to send the user to start the trial (admin panel billing page). */
  billingUrl?: string;
}

type EmailType =
  | 'welcome'
  | 'invitation'
  | 'password-reset'
  | 'payment-success'
  | 'payment-failed'
  | 'subscription-cancelled'
  | 'trial-activation';

type EmailParams =
  | WelcomeParams
  | InvitationParams
  | PasswordResetParams
  | PaymentSuccessParams
  | PaymentFailedParams
  | SubscriptionCancelledParams
  | TrialActivationParams;

interface EmailPayload {
  type: EmailType;
  params: EmailParams;
}

// ─── Branding Constants (clean white theme) ─────────────────────────────────

const BG_OUTER = '#f4f4f5';
const BG_CARD = '#ffffff';
const BG_ELEVATED = '#f8f9fa';
const BORDER_COLOR = '#e5e7eb';
const TEXT_COLOR = '#1a1a2e';
const TEXT_MUTED = '#6b7280';
const ACCENT = '#4f8fff';
const ACCENT_LIGHT = '#eef4ff';
const SUCCESS = '#059669';
const SUCCESS_LIGHT = '#ecfdf5';
const WARNING = '#d97706';
const WARNING_LIGHT = '#fffbeb';
const DANGER = '#dc2626';
const DANGER_LIGHT = '#fef2f2';

// ─── Shared Email Wrapper ────────────────────────────────────────────────────

/**
 * Renders the VaultGuard shield logo as an HTML table structure.
 * Uses a styled Unicode shield character with pure HTML/CSS — no images,
 * no data URIs, no external URLs. Works in all email clients.
 */
function renderLogo(): string {
  return `<table role="presentation" cellpadding="0" cellspacing="0">
  <tr>
    <td style="vertical-align:middle;padding-right:10px;">
      <div style="width:36px;height:36px;background-color:${ACCENT};border-radius:8px;text-align:center;line-height:36px;font-size:20px;color:#ffffff;">&#x1F6E1;</div>
    </td>
    <td style="vertical-align:middle;">
      <span style="font-size:22px;font-weight:700;color:${TEXT_COLOR};letter-spacing:-0.5px;">Vault<span style="color:${ACCENT};">Guard</span></span>
    </td>
  </tr>
</table>`;
}

/**
 * Wraps body HTML in a consistent VaultGuard-branded email layout with
 * white card on light gray background, logo header, and footer.
 */
function renderEmail(title: string, bodyHtml: string): string {
  return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light">
  <meta name="supported-color-schemes" content="light">
  <title>${escapeHtml(title)}</title>
  <!--[if mso]>
  <style>body,table,td{font-family:Arial,Helvetica,sans-serif !important;}</style>
  <![endif]-->
</head>
<body style="margin:0;padding:0;background-color:${BG_OUTER};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;color:${TEXT_COLOR};line-height:1.6;-webkit-text-size-adjust:none;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:${BG_OUTER};">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

          <!-- Header: Shield Logo + VaultGuard -->
          <tr>
            <td align="center" style="padding:0 0 32px 0;">
              ${renderLogo()}
            </td>
          </tr>

          <!-- Body Card -->
          <tr>
            <td style="background-color:${BG_CARD};border-radius:12px;border:1px solid ${BORDER_COLOR};padding:40px 36px;">
              ${bodyHtml}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center" style="padding:28px 0 0 0;">
              <p style="margin:0;font-size:12px;color:${TEXT_MUTED};line-height:1.6;">
                This is a transactional email from VaultGuard.<br>
                You are receiving this because your account or organization requires this notification.
              </p>
              <p style="margin:12px 0 0 0;font-size:12px;color:${TEXT_MUTED};">
                &copy; ${new Date().getFullYear()} VaultGuard &mdash; Encrypted collaboration for Obsidian
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Renders a styled call-to-action button.
 */
function renderButton(text: string, url: string): string {
  return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:28px 0;">
  <tr>
    <td style="background-color:${ACCENT};border-radius:8px;">
      <a href="${escapeHtml(url)}" target="_blank" style="display:inline-block;padding:14px 32px;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;border-radius:8px;">
        ${escapeHtml(text)}
      </a>
    </td>
  </tr>
</table>`;
}

/**
 * Renders a key-value detail row inside an info card.
 */
function renderDetailRow(label: string, value: string): string {
  return `<tr>
  <td style="padding:6px 16px 6px 0;font-size:13px;color:${TEXT_MUTED};width:130px;vertical-align:top;">${escapeHtml(label)}</td>
  <td style="padding:6px 0;font-size:13px;color:${TEXT_COLOR};font-weight:500;">${escapeHtml(value)}</td>
</tr>`;
}

/**
 * Renders an info card with an accent left border.
 */
function renderInfoCard(titleHtml: string, contentHtml: string, accentColor: string = ACCENT): string {
  const bgColor = accentColor === SUCCESS ? SUCCESS_LIGHT
    : accentColor === DANGER ? DANGER_LIGHT
    : accentColor === WARNING ? WARNING_LIGHT
    : ACCENT_LIGHT;
  return `<div style="background-color:${bgColor};border-radius:8px;border:1px solid ${BORDER_COLOR};border-left:3px solid ${accentColor};padding:20px;margin:24px 0;">
  ${titleHtml ? `<p style="margin:0 0 10px 0;font-size:13px;font-weight:600;color:${accentColor};text-transform:uppercase;letter-spacing:0.05em;">${titleHtml}</p>` : ''}
  ${contentHtml}
</div>`;
}

/**
 * Renders a code/slug badge.
 */
function renderBadge(text: string): string {
  return `<code style="display:inline-block;background:${ACCENT_LIGHT};color:${ACCENT};padding:3px 10px;border-radius:6px;font-size:13px;font-family:'SF Mono',Monaco,'Cascadia Code','Courier New',monospace;border:1px solid #dbe8ff;">${escapeHtml(text)}</code>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function normalizeUrlBase(url: string): string {
  return url.replace(/\/+$/, '');
}

function buildInviteUrl(params: InvitationParams): string {
  const adminUrl = normalizeUrlBase(params.adminPanelUrl || 'https://admin.example.com');
  const query = new URLSearchParams({
    invite: '1',
    email: params.username || params.email,
  });

  return `${adminUrl}/#/login?${query.toString()}`;
}

/**
 * Builds the Obsidian deep link the invitee clicks to auto-configure the
 * VaultGuard plugin and start the password-setup flow:
 *   `obsidian://vaultguard-invite?org=<slug>&email=<email>`
 *
 * If the slug is missing we fall back to email-only — `redeemInvite` rejects
 * empty slugs, but the email body's plain-text fallback still gives the user
 * the org name they need to enter manually.
 */
function buildInviteDeepLink(params: InvitationParams): string {
  const query = new URLSearchParams();
  if (params.orgSlug) query.set('org', params.orgSlug);
  const inviteEmail = params.username || params.email;
  if (inviteEmail) query.set('email', inviteEmail);
  return `obsidian://vaultguard-invite?${query.toString()}`;
}

// ─── Email Template Builders ─────────────────────────────────────────────────

function buildWelcomeEmail(params: WelcomeParams): { subject: string; html: string } {
  const subject = `Welcome to VaultGuard, ${params.adminName}!`;
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Welcome to VaultGuard</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Your vault is now cryptographically protected.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};">
      Hi ${escapeHtml(params.adminName)},
    </p>
    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      Your organization <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong> has been created.
      You can now invite team members and start using encrypted collaboration in Obsidian.
    </p>

    ${renderInfoCard('Organization details', `
      <table role="presentation" cellpadding="0" cellspacing="0">
        ${renderDetailRow('Organization', params.orgName)}
        ${renderDetailRow('Slug', params.orgSlug)}
        ${renderDetailRow('Admin', params.adminName)}
      </table>
    `)}

    <p style="margin:0 0 12px 0;font-size:15px;color:${TEXT_COLOR};font-weight:600;">
      Getting started
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 24px 0;">
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">1</span>
          Install the VaultGuard plugin from Obsidian Community Plugins.
        </td>
      </tr>
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">2</span>
          Enter your organization slug ${renderBadge(params.orgSlug)} in the plugin settings.
        </td>
      </tr>
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">3</span>
          Invite your team from the admin panel.
        </td>
      </tr>
    </table>

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      If you have any questions, reply to this email or visit our documentation.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildInvitationEmail(params: InvitationParams): { subject: string; html: string } {
  const subject = `You've been invited to ${params.orgName} on VaultGuard`;
  const deepLink = buildInviteDeepLink(params);
  const adminFallbackUrl = buildInviteUrl(params);
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">You're Invited</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Join your team on VaultGuard.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      <strong style="color:${ACCENT};">${escapeHtml(params.inviterName)}</strong> has invited you to join
      <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong> on VaultGuard &mdash; encrypted collaboration for Obsidian.
    </p>

    ${renderInfoCard('Your account', `
      <table role="presentation" cellpadding="0" cellspacing="0">
        ${renderDetailRow('Username', params.username)}
        ${renderDetailRow('Organization', params.orgName)}
        ${params.orgSlug ? renderDetailRow('Slug', params.orgSlug) : ''}
      </table>
    `)}

    ${renderButton('Open in Obsidian & Set Password', deepLink)}

    <p style="margin:0 0 12px 0;font-size:15px;color:${TEXT_COLOR};font-weight:600;">
      How to get started
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 24px 0;">
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">1</span>
          Install the <strong>VaultGuard</strong> plugin in Obsidian (Settings &rarr; Community plugins).
        </td>
      </tr>
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">2</span>
          Click the button above. Obsidian opens, the plugin auto-configures, and the password-setup screen appears.
        </td>
      </tr>
      <tr>
        <td style="padding:8px 0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
          <span style="display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;border-radius:50%;background:${ACCENT_LIGHT};color:${ACCENT};font-weight:700;font-size:12px;margin-right:10px;border:1px solid #dbe8ff;">3</span>
          Send the verification code to ${renderBadge(params.username)}, enter it, choose your password, and you're in.
        </td>
      </tr>
    </table>

    <div style="background-color:${BG_ELEVATED};border-radius:8px;border:1px solid ${BORDER_COLOR};padding:16px 20px;margin:0 0 16px 0;">
      <p style="margin:0 0 8px 0;font-size:13px;color:${TEXT_COLOR};line-height:1.6;font-weight:600;">
        Button didn't open Obsidian?
      </p>
      <p style="margin:0 0 10px 0;font-size:13px;color:${TEXT_MUTED};line-height:1.6;">
        Install the VaultGuard plugin first, then in Obsidian go to
        <strong style="color:${TEXT_COLOR};">Settings &rarr; VaultGuard &rarr; Redeem invite link</strong>
        and paste this URL:
      </p>
      <p style="margin:0;font-size:12px;color:${TEXT_COLOR};line-height:1.5;word-break:break-all;font-family:'SF Mono',Monaco,'Cascadia Code','Courier New',monospace;background:${BG_CARD};border:1px solid ${BORDER_COLOR};border-radius:6px;padding:10px 12px;">
        ${escapeHtml(deepLink)}
      </p>
    </div>

    <div style="background-color:${BG_ELEVATED};border-radius:8px;border:1px solid ${BORDER_COLOR};padding:16px 20px;margin:0 0 16px 0;">
      <p style="margin:0;font-size:13px;color:${TEXT_MUTED};line-height:1.6;">
        <strong style="color:${TEXT_COLOR};">Prefer the web admin panel?</strong>
        <a href="${escapeHtml(adminFallbackUrl)}" style="color:${ACCENT};">Set your password there</a> instead, then install the plugin and enter the org slug ${params.orgSlug ? renderBadge(params.orgSlug) : ''} in Settings.
      </p>
    </div>

    <div style="background-color:${BG_ELEVATED};border-radius:8px;border:1px solid ${BORDER_COLOR};padding:16px 20px;margin:0 0 16px 0;">
      <p style="margin:0;font-size:13px;color:${TEXT_MUTED};line-height:1.6;">
        <strong style="color:${TEXT_COLOR};">Why no password in this email?</strong> VaultGuard never sends passwords via email. You set your own password using a secure verification code delivered separately.
      </p>
    </div>

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      If you did not expect this invitation, you can safely ignore this email.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildPasswordResetEmail(params: PasswordResetParams): { subject: string; html: string } {
  const subject = 'VaultGuard — Password Reset Code';
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Password Reset</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Use this code to reset your password.</p>

    <p style="margin:0 0 24px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      We received a request to set or reset your VaultGuard password. Enter the code below in VaultGuard to choose a new password:
    </p>

    <div style="text-align:center;margin:32px 0;">
      <div style="display:inline-block;background-color:${ACCENT_LIGHT};border:2px solid ${ACCENT};border-radius:12px;padding:20px 40px;">
        <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:${ACCENT};font-family:'SF Mono',Monaco,'Cascadia Code','Courier New',monospace;">
          ${escapeHtml(params.resetCode)}
        </span>
      </div>
    </div>

    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};text-align:center;">
      This code expires in <strong style="color:${TEXT_COLOR};">${params.expiresInMinutes} minutes</strong>.
    </p>

    <div style="border-top:1px solid ${BORDER_COLOR};margin:24px 0;"></div>

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildPaymentSuccessEmail(params: PaymentSuccessParams): { subject: string; html: string } {
  const subject = `VaultGuard — Payment Receipt for ${params.orgName}`;
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Payment Received</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Thank you for your payment.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      We've successfully processed your payment for <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong>.
    </p>

    ${renderInfoCard('Receipt', `
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
        ${renderDetailRow('Organization', params.orgName)}
        ${renderDetailRow('Plan', params.plan)}
        ${renderDetailRow('Amount', `${params.amount} ${params.currency.toUpperCase()}`)}
        ${renderDetailRow('Invoice Date', params.invoiceDate)}
      </table>
    `, SUCCESS)}

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      If you need a formal invoice, you can download one from the billing portal in your admin panel.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildPaymentFailedEmail(params: PaymentFailedParams): { subject: string; html: string } {
  const subject = `VaultGuard — Payment Failed for ${params.orgName}`;
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Payment Failed</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Action required to maintain access.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      We were unable to process the payment of
      <strong style="color:${TEXT_COLOR};">${escapeHtml(params.amount)} ${escapeHtml(params.currency.toUpperCase())}</strong>
      for <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong>.
    </p>

    ${renderInfoCard('What happens next?', `
      <p style="margin:0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
        We will automatically retry the charge on <strong>${escapeHtml(params.nextRetryDate)}</strong>.
        If the payment continues to fail, your organization's access may be suspended.
      </p>
    `, DANGER)}

    <p style="margin:0 0 8px 0;font-size:15px;color:${TEXT_COLOR};">
      Please update your payment method to avoid any interruption:
    </p>

    ${renderButton('Update Payment Method', params.portalUrl)}

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      If the button above doesn't work, copy and paste this URL into your browser:<br>
      <a href="${escapeHtml(params.portalUrl)}" style="color:${ACCENT};word-break:break-all;font-size:12px;">${escapeHtml(params.portalUrl)}</a>
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildSubscriptionCancelledEmail(params: SubscriptionCancelledParams): { subject: string; html: string } {
  const subject = `VaultGuard — Subscription Cancelled for ${params.orgName}`;
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Subscription Cancelled</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Your plan has been cancelled.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      The VaultGuard subscription for <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong> has been cancelled.
    </p>

    ${renderInfoCard('Important', `
      <p style="margin:0;font-size:14px;color:${TEXT_COLOR};line-height:1.6;">
        Your team will retain access until <strong style="color:${WARNING};">${escapeHtml(params.accessEndDate)}</strong>.
        After that date, encrypted vaults will become read-only and new syncs will be disabled.
      </p>
    `, WARNING)}

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      If this was a mistake or you change your mind, you can resubscribe at any time from the admin panel before access expires.
    </p>

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      We're sorry to see you go. If you have feedback on how we could improve, please reply to this email &mdash; we read every response.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

function buildTrialActivationEmail(params: TrialActivationParams): { subject: string; html: string } {
  const subject = `Your VaultGuard Pro trial is ready, ${params.adminName}`;
  const billingUrl = params.billingUrl || 'https://admin.example.com/#/billing';
  const bodyHtml = `
    <h1 style="margin:0 0 8px 0;font-size:24px;font-weight:700;color:${TEXT_COLOR};">Start your 14-day Pro trial</h1>
    <p style="margin:0 0 24px 0;font-size:14px;color:${TEXT_MUTED};">Every Pro feature, unlocked for 14 days.</p>

    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};">
      Hi ${escapeHtml(params.adminName)},
    </p>
    <p style="margin:0 0 16px 0;font-size:15px;color:${TEXT_COLOR};line-height:1.7;">
      Your organization <strong style="color:${ACCENT};">${escapeHtml(params.orgName)}</strong> is ready
      to start a <strong>14-day VaultGuard Pro trial</strong> &mdash; share links, advanced audit, the
      hosted admin panel, and every other Pro feature unlocked.
    </p>

    ${renderInfoCard('What you get during the trial', `
      <ul style="margin:0;padding-left:20px;font-size:14px;color:${TEXT_COLOR};line-height:1.7;">
        <li>Share links + share-bridge for outside collaborators</li>
        <li>Advanced audit dashboards, alerts, and CSV export</li>
        <li>Hosted web admin panel for non-technical admins</li>
        <li>Up to 100 users and 100 GB of vault storage</li>
        <li>Managed AWS infrastructure with daily backups</li>
      </ul>
    `)}

    ${renderButton('Start trial', billingUrl)}

    <p style="margin:24px 0 16px 0;font-size:13px;color:${TEXT_MUTED};line-height:1.6;">
      If the button doesn't work, paste this into your browser:<br>
      <a href="${escapeHtml(billingUrl)}" style="color:${ACCENT};word-break:break-all;font-size:12px;">${escapeHtml(billingUrl)}</a>
    </p>

    <p style="margin:0 0 12px 0;font-size:13px;color:${TEXT_MUTED};line-height:1.6;">
      Prefer to keep things in your own AWS? Our open-source
      <strong>Community Edition</strong> is free forever &mdash; it includes the full
      encryption, sync, and per-file permissions stack. Pro-only surfaces stay gated off.
    </p>

    <p style="margin:0;font-size:13px;color:${TEXT_MUTED};">
      Questions? Reply to this email &mdash; we read every response.
    </p>`;
  return { subject, html: renderEmail(subject, bodyHtml) };
}

// ─── Email Dispatch ──────────────────────────────────────────────────────────

/**
 * Builds the subject and HTML body for a given email type, then sends it via SES.
 *
 * Exported so other Lambdas can call this directly (in-process) without
 * invoking the email Lambda via the Lambda runtime:
 *
 * ```ts
 * import { sendEmail } from '../email/handler';
 * await sendEmail('welcome', { email: 'admin@acme.com', orgName: 'Acme', orgSlug: 'acme', adminName: 'Alice' });
 * ```
 *
 * @param type - One of the supported email types
 * @param params - Parameters specific to the email type
 */
export async function sendEmail(type: EmailType, params: EmailParams, options?: { throwOnError?: boolean }): Promise<void> {
  let subject: string;
  let html: string;
  let toAddress: string;

  switch (type) {
    case 'welcome': {
      const p = params as WelcomeParams;
      toAddress = p.email;
      ({ subject, html } = buildWelcomeEmail(p));
      break;
    }
    case 'invitation': {
      const p = params as InvitationParams;
      toAddress = p.email;
      ({ subject, html } = buildInvitationEmail(p));
      break;
    }
    case 'password-reset': {
      const p = params as PasswordResetParams;
      toAddress = p.email;
      ({ subject, html } = buildPasswordResetEmail(p));
      break;
    }
    case 'payment-success': {
      const p = params as PaymentSuccessParams;
      toAddress = p.email;
      ({ subject, html } = buildPaymentSuccessEmail(p));
      break;
    }
    case 'payment-failed': {
      const p = params as PaymentFailedParams;
      toAddress = p.email;
      ({ subject, html } = buildPaymentFailedEmail(p));
      break;
    }
    case 'subscription-cancelled': {
      const p = params as SubscriptionCancelledParams;
      toAddress = p.email;
      ({ subject, html } = buildSubscriptionCancelledEmail(p));
      break;
    }
    case 'trial-activation': {
      const p = params as TrialActivationParams;
      toAddress = p.email;
      ({ subject, html } = buildTrialActivationEmail(p));
      break;
    }
    default:
      throw new Error(`Unknown email type: ${type}`);
  }

  const commandInput: Record<string, unknown> = {
    Source: SENDER_EMAIL,
    Destination: {
      ToAddresses: [toAddress],
    },
    Message: {
      Subject: { Data: subject, Charset: 'UTF-8' },
      Body: {
        Html: { Data: html, Charset: 'UTF-8' },
      },
    },
  };

  // Only attach the configuration set if one is configured
  if (SES_CONFIGURATION_SET) {
    commandInput.ConfigurationSetName = SES_CONFIGURATION_SET;
  }

  try {
    await sesClient.send(new SendEmailCommand(commandInput as any));
    console.log(`[EMAIL] Sent ${type} email successfully`);
  } catch (err) {
    // In test mode, surface the error so the caller can see it.
    if (options?.throwOnError) {
      throw err;
    }
    // Email failures are logged but should not crash the calling Lambda.
    console.error(`[EMAIL_SEND_FAILURE] type=${type}`, (err as Error).message);
  }
}

// ─── Lambda Entry Point ──────────────────────────────────────────────────────

/**
 * Lambda handler. Expects an event with a JSON body containing `type` and `params`.
 *
 * This handler is designed for internal invocation (e.g., via Lambda.invoke or
 * EventBridge), not for direct API Gateway exposure.
 *
 * @param event - An object with a `body` property (JSON string) or direct { type, params }
 * @returns A result object indicating success or failure
 */
export async function handler(
  event: { body?: string; type?: string; params?: Record<string, unknown> }
): Promise<{ statusCode: number; body: string }> {
  try {
    let payload: EmailPayload;

    if (event.body) {
      // Invoked via API-style payload (body is a JSON string)
      payload = JSON.parse(event.body) as EmailPayload;
    } else if (event.type && event.params) {
      // Invoked directly via Lambda.invoke with a structured event
      payload = { type: event.type as EmailType, params: event.params as unknown as EmailParams };
    } else {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Missing required fields: type, params' }),
      };
    }

    if (!payload.type || !payload.params) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Missing required fields: type, params' }),
      };
    }

    await sendEmail(payload.type, payload.params);

    return {
      statusCode: 200,
      body: JSON.stringify({ message: `Email sent: ${payload.type}` }),
    };
  } catch (err) {
    console.error('[EMAIL_HANDLER_ERROR]', (err as Error).message);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Failed to send email',
        message: err instanceof Error ? err.message : 'Unknown error',
      }),
    };
  }
}
