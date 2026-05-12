import type { APIGatewayProxyEvent } from 'aws-lambda';

export interface UsersRouteContext {
  path: string;
  userId?: string;
  action?: string;
  orgId?: string;
}

type GatewayEventWithRawPath = APIGatewayProxyEvent & {
  rawPath?: string;
};

function isConcretePathSegment(value?: string | null): value is string {
  return !!value && !/^\{[^/]+\}$/.test(value);
}

function decodePathSegment(value?: string | null): string | undefined {
  if (!isConcretePathSegment(value)) {
    return undefined;
  }

  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeGatewayPath(path: string | undefined, stage: string | undefined): string {
  if (!path) {
    return '';
  }

  const withoutQuery = path.split('?')[0]?.split('#')[0] ?? '';
  if (!withoutQuery) {
    return '';
  }

  const normalized = withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
  if (!stage || stage === '$default') {
    return normalized;
  }

  const stagePrefix = `/${stage}`;
  if (normalized === stagePrefix) {
    return '/';
  }
  if (normalized.startsWith(`${stagePrefix}/`)) {
    return normalized.slice(stagePrefix.length);
  }

  return normalized;
}

function getPathSegments(path: string): string[] {
  return path
    .split('/')
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0);
}

function extractPathSegment(
  path: string,
  rootSegment: string,
  segmentIndex: number
): string | undefined {
  const segments = getPathSegments(path);
  if (segments[0] !== rootSegment || segments.length <= segmentIndex) {
    return undefined;
  }

  return decodePathSegment(segments[segmentIndex]);
}

export function resolveUsersRouteContext(event: APIGatewayProxyEvent): UsersRouteContext {
  const gatewayEvent = event as GatewayEventWithRawPath;
  const requestContext = event.requestContext as APIGatewayProxyEvent['requestContext'] & {
    path?: string;
  };
  const stage = event.requestContext?.stage;

  const pathCandidates = [
    gatewayEvent.rawPath,
    requestContext.path,
    event.path,
    event.resource,
  ]
    .map((candidate) => normalizeGatewayPath(candidate, stage))
    .filter((candidate) => candidate.length > 0);

  const concretePath = pathCandidates.find((candidate) => !candidate.includes('{'));
  const path = concretePath || pathCandidates[0] || '';

  return {
    path,
    userId:
      decodePathSegment(event.pathParameters?.userId) ||
      extractPathSegment(path, 'users', 1),
    action:
      decodePathSegment(event.pathParameters?.action) ||
      extractPathSegment(path, 'users', 2),
    orgId:
      decodePathSegment(event.pathParameters?.orgId) ||
      extractPathSegment(path, 'orgs', 1),
  };
}
