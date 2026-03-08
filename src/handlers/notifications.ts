import { AuthService } from '../services/auth';
import type { Env } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';

function extractAccessToken(request: Request): string | null {
  const url = new URL(request.url);
  const queryToken = String(url.searchParams.get('access_token') || '').trim();
  if (queryToken) return queryToken;

  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

async function authenticateNotificationsRequest(request: Request, env: Env): Promise<string | null> {
  const accessToken = extractAccessToken(request);
  if (!accessToken) return null;

  const auth = new AuthService(env);
  const payload = await auth.verifyAccessToken(`Bearer ${accessToken}`);
  return payload?.sub || null;
}

export async function handleNotificationsNegotiate(request: Request, env: Env): Promise<Response> {
  const userId = await authenticateNotificationsRequest(request, env);
  if (!userId) return errorResponse('Unauthorized', 401);

  const connectionId = generateUUID();
  return jsonResponse({
    connectionId,
    connectionToken: connectionId,
    negotiateVersion: 1,
    availableTransports: [
      {
        transport: 'WebSockets',
        transferFormats: ['Text', 'Binary'],
      },
    ],
  });
}

export async function handleNotificationsHub(request: Request, env: Env): Promise<Response> {
  const userId = await authenticateNotificationsRequest(request, env);
  if (!userId) return errorResponse('Unauthorized', 401);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const id = env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  await stub.fetch('https://notifications/internal/bind-user', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-NodeWarden-UserId': userId,
    },
    body: JSON.stringify({ userId }),
  });
  return stub.fetch(request);
}
