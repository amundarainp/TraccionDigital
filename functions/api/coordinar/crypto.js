/**
 * TD · Módulo Criptográfico y Validador Canónico para Coordinación
 * 
 * Unifica el contrato criptográfico entre generador de enlaces (servidor/ManyChat)
 * y el validador del endpoint servidor (Cloudflare Pages Functions / Workers).
 *
 * ESPECIFICACIÓN:
 * - Algoritmo: HMAC-SHA256
 * - Campos a firmar en orden canónico estricto:
 *     lead_uid + "|" + solicitud_id + "|" + expiration_timestamp
 * - Codificación: UTF-8 en entrada, salida en Hexadecimal en minúsculas.
 * - Expiración: Timestamp Unix en segundos.
 */

// Normalización canónica de los datos para la firma
export function buildSignaturePayload(leadUid, solicitudId, exp) {
  const cleanUid = String(leadUid || '').trim();
  const cleanReq = String(solicitudId || '').trim();
  const cleanExp = String(exp || '').trim();
  return `${cleanUid}|${cleanReq}|${cleanExp}`;
}

// Generación HMAC-SHA256 compatible con Web Crypto API (Nativo Cloudflare / Node 18+)
export async function generateHmacSha256(dataString, secretKey) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secretKey);
  const messageData = encoder.encode(dataString);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Comparación en tiempo constante para mitigar timing attacks
export function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aClean = a.trim().toLowerCase();
  const bClean = b.trim().toLowerCase();
  if (aClean.length !== bClean.length) return false;

  let result = 0;
  for (let i = 0; i < aClean.length; i++) {
    result |= aClean.charCodeAt(i) ^ bClean.charCodeAt(i);
  }
  return result === 0;
}

// Validador integral de enlace firmado
export async function verifySignedToken({ leadUid, solicitudId, exp, sig, secretKey, nowSeconds = Math.floor(Date.now() / 1000) }) {
  if (!leadUid || typeof leadUid !== 'string' || !leadUid.startsWith('TD_')) {
    return { valid: false, code: 'INVALID_IDENTITY', error: 'Identidad lead_uid inválida o no canónica.' };
  }

  if (!solicitudId || typeof solicitudId !== 'string') {
    return { valid: false, code: 'INVALID_REQUEST_ID', error: 'Identificador solicitud_id ausente.' };
  }

  const expInt = parseInt(exp, 10);
  if (isNaN(expInt) || expInt <= 0) {
    return { valid: false, code: 'INVALID_EXPIRATION', error: 'Timestamp de expiración inválido.' };
  }

  // Verificación de expiración
  if (nowSeconds > expInt) {
    return { valid: false, code: 'LINK_EXPIRED', error: 'El enlace de solicitud ha expirado.' };
  }

  if (!sig || typeof sig !== 'string') {
    return { valid: false, code: 'MISSING_SIGNATURE', error: 'Firma de autenticación ausente.' };
  }

  if (!secretKey || typeof secretKey !== 'string') {
    return { valid: false, code: 'SERVER_MISCONFIGURED', error: 'Clave secreta del servidor no configurada.' };
  }

  const expectedData = buildSignaturePayload(leadUid, solicitudId, expInt);
  const expectedSignature = await generateHmacSha256(expectedData, secretKey);

  const isMatch = timingSafeEqualHex(sig, expectedSignature);
  if (!isMatch) {
    return { valid: false, code: 'SIGNATURE_MISMATCH', error: 'Firma digital inválida o manipulada.' };
  }

  return { valid: true };
}
