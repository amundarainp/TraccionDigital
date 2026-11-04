/**
 * TD · Cloudflare Pages Function: Endpoint /api/coordinar/solicitar
 * 
 * RESPONSABILIDAD:
 * 1. Recibir solicitud desde coordinar/index.html.
 * 2. Validar firma criptográfica HMAC-SHA256 y expiración con la clave del servidor.
 * 3. Proteger la idempotencia transaccional (D1 con PRIMARY KEY).
 * 4. SEPARACIÓN ESTRICTA Y VERIFICACIÓN REAL:
 *    - Un HTTP 200 genérico de Make solo confirma recepción (acuse de recibo).
 *    - Para clasificar como 'registered', debe verificarse el contrato de Dedupe:
 *      { ok: true, status: "registered", dedupe_escritura_confirmada: true, sheet_row_updated: ... }
 * 5. CONCILIACIÓN DE SOLICITUDES EN TIMEOUT O FALLO PARCIAL:
 *    - Si un reintento ingresa con solicitud en 'timeout' o 'failed_dedupe' pero con Calendar ya creado,
 *      reconcilia hacia Dedupe reutilizando `calendar_event_id` sin crear un segundo evento Calendar.
 */

import { verifySignedToken } from './crypto.js';
import { robustIdempotencyStore } from './idempotency.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const secretKey = env?.TD_COORDINAR_HMAC_SECRET || 'TD_LOCAL_DEV_SECRET_KEY_FOR_TESTS_2026';

  let body;
  try {
    body = await request.json();
  } catch (err) {
    return jsonResponse({ ok: false, error: 'JSON malformado o cuerpo ausente.', code: 'BAD_REQUEST' }, 400);
  }

  const {
    solicitud_id,
    fecha_solicitada,
    hora_solicitada,
    timezone = 'America/Argentina/Buenos_Aires',
    lead_uid,
    exp,
    sig,
    source = 'formulario_coordinar',
    source_canal = 'web',
    source_accion = 'reunion_agendada'
  } = body || {};

  // 1. Identidad Canónica Obligatoria
  if (!lead_uid || typeof lead_uid !== 'string' || !lead_uid.startsWith('TD_')) {
    return jsonResponse({
      ok: false,
      error: 'Identidad lead_uid inválida o ausente.',
      code: 'INVALID_IDENTITY'
    }, 400);
  }

  // 2. Verificación Criptográfica HMAC-SHA256 y Expiración
  const verification = await verifySignedToken({
    leadUid: lead_uid,
    solicitudId: solicitud_id,
    exp,
    sig,
    secretKey
  });

  if (!verification.valid) {
    const statusCode = (verification.code === 'LINK_EXPIRED') ? 403 : 401;
    return jsonResponse({
      ok: false,
      error: verification.error,
      code: verification.code
    }, statusCode);
  }

  // 3. Adquisición de Lock Atómico de Idempotencia
  const lock = await robustIdempotencyStore.acquire(lead_uid, solicitud_id, env);
  
  // Variables de conciliación si la solicitud estaba en timeout previo
  let isReconciliation = false;
  let existingCalendarData = null;

  if (!lock.ok) {
    if (lock.alreadyProcessed) {
      // Replay idempotente de solicitud ya registrada con confirmación verificable
      return jsonResponse({
        ok: true,
        status: 'registered',
        idempotent_replay: true,
        message: 'Solicitud ya procesada y confirmada en CRM previamente.',
        data: lock.record.result
      }, 200);
    }
    
    // Si la solicitud sufrió timeout o falla en Dedupe pero es reconciliable
    if (lock.isReconcilable) {
      isReconciliation = true;
      existingCalendarData = lock.calendarData || {};
    } else if (lock.inFlight) {
      return jsonResponse({
        ok: false,
        status: 'in_flight',
        error: 'Hay una solicitud idéntica siendo procesada en este momento. Por favor aguarde.',
        code: 'CONFLICT_IN_FLIGHT'
      }, 409);
    } else {
      return jsonResponse({ ok: false, error: 'Parámetros de solicitud inválidos.', code: 'INVALID_PARAMS' }, 400);
    }
  }

  // 4. Validación de Fechas y Horarios
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!fecha_solicitada || !dateRegex.test(fecha_solicitada)) {
    if (!isReconciliation) await robustIdempotencyStore.releasePreDispatch(lead_uid, solicitud_id, env);
    return jsonResponse({ ok: false, error: 'Formato de fecha_solicitada inválido (YYYY-MM-DD).', code: 'INVALID_DATE' }, 400);
  }

  const timeRegex = /^([01]\d|2[0-3]):[0-5]\d$/;
  if (!hora_solicitada || !timeRegex.test(hora_solicitada)) {
    if (!isReconciliation) await robustIdempotencyStore.releasePreDispatch(lead_uid, solicitud_id, env);
    return jsonResponse({ ok: false, error: 'Formato de hora_solicitada inválido (HH:MM).', code: 'INVALID_TIME' }, 400);
  }

  const [year, month, day] = fecha_solicitada.split('-').map(Number);
  const targetDate = new Date(year, month - 1, day);
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  if (targetDate <= today) {
    if (!isReconciliation) await robustIdempotencyStore.releasePreDispatch(lead_uid, solicitud_id, env);
    return jsonResponse({
      ok: false,
      error: 'La fecha seleccionada no puede ser pasada ni del mismo día.',
      code: 'PAST_DATE_NOT_ALLOWED'
    }, 400);
  }

  // 5. Preparar Payload Canónico hacia Make (TD_Gestion_Comercial_v1)
  const [h, m] = hora_solicitada.split(':');
  const dayPad = String(day).padStart(2, '0');
  const monthPad = String(month).padStart(2, '0');
  const fechaReunionCanonico = `${dayPad}/${monthPad}/${year} ${h}:${m}:00`;

  const outboundMakePayload = {
    event_type: 'td_gestion_comercial',
    source,
    source_canal,
    source_accion: 'reunion_agendada',
    solicitud_id,
    lead_uid,
    fecha_solicitada,
    hora_solicitada,
    fecha_reunion: fechaReunionCanonico,
    timezone: 'America/Argentina/Buenos_Aires',
    tipo_coordinacion: 'solicitud_contacto',
    is_reconciliation: isReconciliation,
    existing_calendar_id: existingCalendarData?.calendar_event_id || null,
    timestamp_recepcion: new Date().toISOString()
  };

  const makeWebhookUrl = env?.TD_GESTION_COMERCIAL_WEBHOOK_URL;

  // 6. Modo Sin Conexión a Make (Offline / Prepared)
  if (!makeWebhookUrl || env?.TD_MOCK_MAKE_OFFLINE === 'true') {
    const preparedData = {
      solicitud_id,
      lead_uid,
      fecha_reunion: fechaReunionCanonico,
      timezone,
      status: 'prepared',
      message: 'Solicitud validada por el servidor, pero pendiente de registro por sistema receptor.',
      outbound_payload: outboundMakePayload
    };

    if (!isReconciliation) await robustIdempotencyStore.releasePreDispatch(lead_uid, solicitud_id, env);

    return jsonResponse({
      ok: true,
      status: 'prepared',
      message: 'Solicitud validada criptográficamente, pendiente de registro en Make.',
      data: preparedData
    }, 200);
  }

  // 7. Despacho hacia Make con Inspección de Confirmación Verificable
  let makeResponse;
  let responseJson = null;

  try {
    if (typeof env?.__mockMakeFetch === 'function') {
      makeResponse = await env.__mockMakeFetch(makeWebhookUrl, outboundMakePayload);
      try {
        responseJson = await makeResponse.json();
      } catch (e) {
        responseJson = null;
      }
    } else {
      makeResponse = await fetch(makeWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(outboundMakePayload)
      });
      try {
        responseJson = await makeResponse.json();
      } catch (e) {
        responseJson = null;
      }
    }
  } catch (networkErr) {
    // FALLO PARCIAL: Timeout o corte de red hacia Make
    // Preservar en estado 'timeout' (NO borrar) para evitar segundo Calendar
    await robustIdempotencyStore.markTimeout(lead_uid, solicitud_id, existingCalendarData || {}, {
      message: networkErr.message,
      timestamp: new Date().toISOString()
    }, env);

    return jsonResponse({
      ok: false,
      status: 'timeout_pending',
      error: 'La comunicación con el sistema de agenda experimentó un retraso. Tu solicitud ha quedado resguardada para conciliación.',
      code: 'MAKE_TIMEOUT'
    }, 504);
  }

  // Si Make devolvió un error de transporte HTTP (5xx / 4xx)
  if (!makeResponse || !makeResponse.ok) {
    if (!isReconciliation) await robustIdempotencyStore.releasePreDispatch(lead_uid, solicitud_id, env);
    return jsonResponse({
      ok: false,
      status: 'error_make_rejected',
      error: 'El sistema receptor rechazó la solicitud.',
      code: 'MAKE_REJECTED',
      http_status: makeResponse?.status
    }, 502);
  }

  // 8. VERIFICACIÓN DEL CONTRATO DE PERSISTENCIA EFECTIVA DE DEDUPE
  // Distinguir entre simple acuse de recibo HTTP 200 vs confirmación auténtica de Dedupe
  const hasAuthenticConfirmation = responseJson?.ok === true &&
                                   responseJson?.dedupe_escritura_confirmada === true &&
                                   Boolean(responseJson?.sheet_row_updated);

  // Si Make solo respondió con acuse de recepción genérico (sin confirmar escritura real de Dedupe)
  if (!hasAuthenticConfirmation) {
    // Si la respuesta de Make trajo datos de Calendar pero Dedupe falló o no confirmó
    if (responseJson?.calendar_event_id) {
      await robustIdempotencyStore.markFailedDedupe(lead_uid, solicitud_id, {
        calendar_event_id: responseJson.calendar_event_id,
        calendar_event_link: responseJson.calendar_event_link
      }, env);
    }

    return jsonResponse({
      ok: true,
      status: 'prepared',
      message: 'Solicitud recibida por el sistema receptor, pero sin confirmación verificada de escritura en CRM.',
      data: {
        solicitud_id,
        lead_uid,
        acuse_recibo: true,
        dedupe_escritura_confirmada: false,
        raw_response: responseJson
      }
    }, 200);
  }

  // 9. CONFIRMACIÓN AUTÉNTICA Y DEFINITIVA ('registered')
  const registeredData = {
    solicitud_id,
    lead_uid,
    fecha_reunion: fechaReunionCanonico,
    timezone,
    status: 'registered',
    dedupe: {
      escritura_confirmada: true,
      row_number: responseJson.sheet_row_updated,
      lead_uid: responseJson.lead_uid
    },
    calendar: {
      calendar_event_id: responseJson.calendar_event_id,
      calendar_event_link: responseJson.calendar_event_link,
      calendar_event_creado: 'si'
    },
    is_reconciled: isReconciliation,
    outbound_payload: outboundMakePayload
  };

  // Consolidar registro exitoso en almacén de idempotencia
  await robustIdempotencyStore.commit(lead_uid, solicitud_id, registeredData, env);

  return jsonResponse({
    ok: true,
    status: 'registered',
    message: 'Solicitud confirmada y registrada fehacientemente en CRM y Calendar.',
    data: registeredData
  }, 200);
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Requested-With'
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
