import { RequestUrlResponse, requestUrl } from "obsidian";
import { SAAS_DEFAULTS } from "../config/saas-defaults";

const COMMON_STAGE_SUFFIXES = [
  "dev",
  "prod",
  "staging",
  "stage",
  "test",
  "qa",
  "development",
  "production",
] as const;

const UI_ROUTE_SEGMENTS = new Set([
  "users",
  "permissions",
  "audit",
  "settings",
  "login",
  "index.html",
]);

const API_ROUTE_SEGMENTS = new Set([
  "auth",
  "files",
  "permissions",
  "audit",
  "users",
  "vaults",
  "orgs",
  "billing",
  "re-encryption",
  "signup",
]);

export function normalizeVaultGuardApiBaseUrl(baseUrl: string): string {
  const trimmedBaseUrl = baseUrl.trim();
  if (!trimmedBaseUrl) {
    return "";
  }

  let parsedBaseUrl: URL;
  try {
    parsedBaseUrl = new URL(trimmedBaseUrl);
  } catch {
    return trimmedBaseUrl.replace(/\/+$/, "");
  }

  const discardWebsitePath = rewriteLikelyWebsiteHostToApiHost(parsedBaseUrl);

  const rawPathSegments = discardWebsitePath
    ? []
    : getRawPathSegments(parsedBaseUrl.pathname);
  const pathSegments = rawPathSegments.map((segment) => segment.toLowerCase());
  const normalizedPathSegments = collapseToLikelyBasePathSegments(
    rawPathSegments,
    pathSegments
  );

  parsedBaseUrl.pathname =
    normalizedPathSegments.length > 0
      ? `/${normalizedPathSegments.join("/")}`
      : "";
  parsedBaseUrl.search = "";
  parsedBaseUrl.hash = "";

  return parsedBaseUrl.toString().replace(/\/+$/, "");
}

export async function resolveVaultGuardApiBaseUrl(
  baseUrl: string,
  idToken?: string,
  probePath?: string
): Promise<string> {
  const normalizedBaseUrl = normalizeVaultGuardApiBaseUrl(baseUrl);
  if (!normalizedBaseUrl || !idToken) {
    return normalizedBaseUrl;
  }

  let parsedBaseUrl: URL;
  try {
    parsedBaseUrl = new URL(normalizedBaseUrl);
  } catch {
    return normalizedBaseUrl;
  }

  const candidates = buildCandidateBaseUrls(parsedBaseUrl);

  for (const candidate of candidates) {
    if (await isReachableVaultGuardApiBase(candidate, idToken, probePath)) {
      return candidate;
    }
  }

  return normalizedBaseUrl;
}

function appendPathSegment(baseUrl: URL, segment: string): string {
  const candidate = new URL(baseUrl.toString());
  candidate.pathname = `/${segment}`;
  candidate.search = "";
  candidate.hash = "";
  return candidate.toString().replace(/\/+$/, "");
}

function rewriteLikelyWebsiteHostToApiHost(baseUrl: URL): boolean {
  const hostname = baseUrl.hostname.toLowerCase();

  if (SAAS_DEFAULTS.apiHostname && SAAS_DEFAULTS.websiteHostnames.includes(hostname)) {
    baseUrl.hostname = SAAS_DEFAULTS.apiHostname;
    return true;
  }

  if (hostname.startsWith("admin.")) {
    baseUrl.hostname = `api.${baseUrl.hostname.slice("admin.".length)}`;
  }

  return false;
}

function buildCandidateBaseUrls(baseUrl: URL): string[] {
  const pathSegments = getPathSegments(baseUrl.pathname);
  const candidates = new Set<string>();
  const originRoot = withPathSegments(baseUrl, []);

  candidates.add(normalizeVaultGuardApiBaseUrl(baseUrl.toString()));

  if (pathSegments.length === 0) {
    addCommonStageCandidates(candidates, baseUrl);
    return [...candidates];
  }

  const firstSegment = pathSegments[0];
  const secondSegment = pathSegments[1];

  if (looksLikeUiSegment(firstSegment) || looksLikeApiSegment(firstSegment)) {
    candidates.add(originRoot);
  } else {
    candidates.add(withPathSegments(baseUrl, [firstSegment]));
    candidates.add(originRoot);
  }

  if (
    secondSegment &&
    !looksLikeApiSegment(firstSegment) &&
    !looksLikeUiSegment(firstSegment) &&
    (looksLikeUiSegment(secondSegment) || looksLikeApiSegment(secondSegment))
  ) {
    candidates.add(withPathSegments(baseUrl, [firstSegment]));
  }

  if (pathSegments[pathSegments.length - 1] === "index.html") {
    if (pathSegments.length > 1) {
      candidates.add(withPathSegments(baseUrl, pathSegments.slice(0, -1)));
    } else {
      candidates.add(originRoot);
    }
  }

  addCommonStageCandidates(candidates, baseUrl);
  addCommonStageCandidates(candidates, new URL(originRoot));

  return [...candidates];
}

function addCommonStageCandidates(candidates: Set<string>, baseUrl: URL): void {
  const pathSegments = getPathSegments(baseUrl.pathname);
  if (pathSegments.length > 1) {
    return;
  }

  const firstSegment = pathSegments[0];
  if (firstSegment && !looksLikeLikelyStageSegment(firstSegment)) {
    return;
  }

  const rootUrl = new URL(baseUrl.toString());
  rootUrl.pathname = "";
  rootUrl.search = "";
  rootUrl.hash = "";

  for (const stage of COMMON_STAGE_SUFFIXES) {
    candidates.add(appendPathSegment(rootUrl, stage));
  }
}

function withPathSegments(baseUrl: URL, segments: string[]): string {
  const candidate = new URL(baseUrl.toString());
  candidate.pathname = segments.length > 0 ? `/${segments.join("/")}` : "";
  candidate.search = "";
  candidate.hash = "";
  return normalizeVaultGuardApiBaseUrl(candidate.toString());
}

function getPathSegments(pathname: string): string[] {
  return getRawPathSegments(pathname).map((segment) => segment.toLowerCase());
}

function getRawPathSegments(pathname: string): string[] {
  return pathname
    .split("/")
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);
}

function collapseToLikelyBasePathSegments(
  rawPathSegments: string[],
  normalizedPathSegments: string[]
): string[] {
  const firstKnownRouteSegmentIndex = normalizedPathSegments.findIndex(
    (segment) => looksLikeUiSegment(segment) || looksLikeApiSegment(segment)
  );

  if (firstKnownRouteSegmentIndex === -1) {
    return rawPathSegments;
  }

  if (firstKnownRouteSegmentIndex === 0) {
    return [];
  }

  return rawPathSegments.slice(0, firstKnownRouteSegmentIndex);
}

function looksLikeUiSegment(segment: string | undefined): boolean {
  return !!segment && UI_ROUTE_SEGMENTS.has(segment.toLowerCase());
}

function looksLikeApiSegment(segment: string | undefined): boolean {
  return !!segment && API_ROUTE_SEGMENTS.has(segment.toLowerCase());
}

function looksLikeLikelyStageSegment(segment: string): boolean {
  if (looksLikeUiSegment(segment) || looksLikeApiSegment(segment)) {
    return false;
  }

  return !segment.includes(".");
}

async function isReachableVaultGuardApiBase(
  baseUrl: string,
  idToken: string,
  probePath?: string
): Promise<boolean> {
  try {
    const path = probePath ?? "/vaults";
    const response = await requestUrl({
      url: `${baseUrl}${path}`,
      method: "GET",
      headers: { Authorization: idToken },
      throw: false,
    });

    return looksLikeVaultGuardApiResponse(response);
  } catch {
    return false;
  }
}

function looksLikeVaultGuardApiResponse(response: RequestUrlResponse): boolean {
  const contentType =
    getHeaderValue(response.headers, "content-type")?.toLowerCase() ?? "";
  const requestId = getHeaderValue(response.headers, "x-request-id");
  const jsonBody = isRecord(response.json) ? response.json : null;
  const bodyText = response.text ?? "";
  const message =
    typeof jsonBody?.message === "string" ? jsonBody.message : bodyText;

  if (looksLikeAwsSignatureError(message, bodyText, contentType)) {
    return false;
  }

  if (response.status >= 500 || response.status === 404) {
    return false;
  }

  if (contentType.includes("application/json")) {
    return true;
  }

  if (requestId) {
    return true;
  }

  if (
    jsonBody &&
    (
      Array.isArray(jsonBody.rules) ||
      typeof jsonBody.message === "string" ||
      typeof jsonBody.error === "string"
    )
  ) {
    return true;
  }

  return false;
}

export function looksLikeAwsSignatureError(
  message: string,
  bodyText: string,
  contentType: string
): boolean {
  const haystack = `${message}\n${bodyText}`.toLowerCase();
  // Strict SigV4 markers (specific parameter names AWS only emits for sigv4)
  // OR clear "you pasted a website URL" signals (HTML/XML body).
  //
  // NB: "hashed with sha-256" alone is too broad — API Gateway emits it on
  // every malformed-Authorization-header response, including "Invalid
  // key=value pair (missing equal-sign)" returned for routes that have
  // drifted to AWS_IAM auth or for any case where a valid Bearer token
  // wasn't accepted. Treating that as "misrouted URL" makes the plugin
  // surface a confusing "check your API endpoint" error when the real
  // problem is an auth failure on a specific endpoint.
  return (
    haystack.includes("authorization header requires 'credential' parameter") ||
    haystack.includes("authorization header requires 'signature' parameter") ||
    haystack.includes("authorization header requires 'signedheaders' parameter") ||
    haystack.includes("x-amz-date") ||
    contentType.includes("xml") ||
    contentType.includes("text/html") ||
    bodyText.trim().startsWith("<")
  );
}

function getHeaderValue(headers: Record<string, string>, name: string): string | null {
  const entry = Object.entries(headers).find(
    ([headerName]) => headerName.toLowerCase() === name.toLowerCase()
  );
  return entry?.[1] ?? null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
