/**
 * TD · Cloudflare Pages Function: Endpoint /api/coordinar/firmar
 * 
 * RESPONSABILIDAD:
 * Generar enlace firmado con HMAC-SHA256 para ManyChat o backend autorizado.
 * 
 * SEGURIDAD Y AUTENTICACIÓN:
 * - Requiere OBLIGATORIAMENTE un header de autorización:
 *   - 'Authorization: Bearer <API_KEY>' o
 *   - 'X-TD-API-Key: <API_KEY>'
 * - Validado estrictamente contra env.TD_INTERNAL_API_KEY.
 * - Si no está provisto o no coincide, responde HTTP 401 UNAUTHORIZED inmediatamente.
 * - Sin secretos expuestos en el navegador ni en mensajes al prospecto.
 * 
 * PARÁMETROS DE ENTRADA (JSON):
 * - lead_uid: (Obligatorio) ej. "TD_5491152265440"
 * - ttl_hours: (Opcional) Duración del enlace en horas (default: 72 horas)
 * - base_url: (Opcional) URL base del formulario (default: "https://www.traccion-digital.com.ar/coordinar")
 * 
 * SALIDA (JSON):
 * {
 *   "ok": true,
 *   "url": "https://www.traccion-digital.com.ar/coordinar?uid=...&req=...&exp=...&sig=...",
 *   "params": {
 *     "uid": "...",
 *     "req": "...",
 *     "exp": 1234567890,
 *     "sig": "..."
 *   }
 * }
 */

import { buildSignaturePayload, generateHmacSha256 } from './crypto.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const secretKey = env?.TD_COORDINAR_HMAC_SECRET || 'TD_LOCAL_DEV_SECRET_KEY_FOR_TESTS_2026';
  const internalApiKey = env?.TD_INTERNAL_API_KEY || 'TD_INTERNAL_KEY_DEFAULT_2026';

  // 1. Verificación obligatoria de autenticación interna
  const authHeader = request.headers.get('Authorization') || '';
  const xApiKey = request.headers.get('X-TD-API-Key') || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  const isAuthorized = (token && token === internalApiKey) || (xApiKey && xApiKey === internalApiKey);

  if (!isAuthorized) {
    return jsonResponse({
      ok: false,
      error: 'Acceso no autorizado al generador de firmas.',
      code: 'UNAUTHORIZED'
    }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (err) {
    return jsonResponse({ ok: false, error: 'JSON malformado o cuerpo ausente.', code: 'BAD_REQUEST' }, 400);
  }

  const {
    lead_uid,
    ttl_hours = 72,
    base_url = 'https://www.traccion-digital.com.ar/coordinar'
  } = body || {};

  // 2. Identidad Canónica Obligatoria
  if (!lead_uid || typeof lead_uid !== 'string' || !lead_uid.startsWith('TD_')) {
    return jsonResponse({
      ok: false,
      error: 'Identidad lead_uid inválida o ausente (debe comenzar con TD_).',
      code: 'INVALID_IDENTITY'
    }, 400);
  }

  // 3. Generar solicitud_id único (REQ-<random_hex>)
  const randomBytes = new Uint8Array(6);
  crypto.getRandomValues(randomBytes);
  const randomHex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const solicitudId = `REQ-${randomHex}`;

  // 4. Calcular timestamp de expiración (Unix epoch en segundos)
  const nowSeconds = Math.floor(Date.now() / 1000);
  const ttlSeconds = Math.max(1, parseInt(ttl_hours, 10) || 72) * 3600;
  const exp = nowSeconds + ttlSeconds;

  // 5. Calcular firma HMAC-SHA256 según contrato canónico
  const payloadToSign = buildSignaturePayload(lead_uid, solicitudId, exp);
  const sig = await generateHmacSha256(payloadToSign, secretKey);

  // 6. Construir URL firmada
  const urlObj = new URL(base_url);
  urlObj.searchParams.set('uid', lead_uid);
  urlObj.searchParams.set('req', solicitudId);
  urlObj.searchParams.set('exp', String(exp));
  urlObj.searchParams.set('sig', sig);

  const signedUrl = urlObj.toString();

  return jsonResponse({
    ok: true,
    url: signedUrl,
    params: {
      uid: lead_uid,
      req: solicitudId,
      exp,
      sig
    }
  }, 200);
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-TD-API-Key'
    }
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
