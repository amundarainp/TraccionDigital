/**
 * TD · Módulo de Almacén de Idempotencia y Conciliación Robusta con D1
 *
 * ESPECIFICACIÓN:
 * - Tabla: `coordinar_idempotencia`
 * - PRIMARY KEY: (lead_uid, solicitud_id)
 * - Estados gestionados:
 *     1. 'in_flight': Petición en proceso de validación / despacho.
 *     2. 'registered': Confirmada fehacientemente con persistencia en CRM / Calendar.
 *     3. 'timeout': Falla de red / timeout tras despacho; resguardada para conciliación.
 *     4. 'failed_dedupe': Calendar creado pero fallo al persistir en Dedupe.
 */

export class RobustIdempotencyStore {
  constructor(defaultTtlSeconds = 86400) {
    this.defaultTtlSeconds = defaultTtlSeconds;
    this.records = new Map(); // clave: `${leadUid}::${solicitudId}`
  }

  _getKey(leadUid, solicitudId) {
    return `${String(leadUid || '').trim()}::${String(solicitudId || '').trim()}`;
  }

  /**
   * Intenta adquirir lock de procesamiento atómico.
   * Con Cloudflare D1 (env.DB), utiliza INSERT atómico.
   */
  async acquire(leadUid, solicitudId, env) {
    if (!leadUid || !solicitudId) {
      return { ok: false, reason: 'MISSING_PARAMS' };
    }

    const key = this._getKey(leadUid, solicitudId);

    // 1. Integración Cloudflare D1
    if (env?.DB) {
      try {
        const stmt = env.DB.prepare(`
          INSERT INTO coordinar_idempotencia (lead_uid, solicitud_id, status, created_at)
          VALUES (?, ?, 'in_flight', ?)
        `);
        await stmt.bind(leadUid, solicitudId, Date.now()).run();
        return { ok: true, driver: 'd1' };
      } catch (d1Err) {
        // Violación de PRIMARY KEY -> comprobar estado
        try {
          const row = await env.DB.prepare(`
            SELECT status, result_json, calendar_data FROM coordinar_idempotencia
            WHERE lead_uid = ? AND solicitud_id = ?
          `).bind(leadUid, solicitudId).first();

          if (row?.status === 'registered') {
            return {
              ok: false,
              alreadyProcessed: true,
              record: { status: 'registered', result: JSON.parse(row.result_json || '{}') },
              driver: 'd1'
            };
          }
          if (row?.status === 'timeout' || row?.status === 'failed_dedupe') {
            return {
              ok: false,
              inFlight: true,
              status: row.status,
              isReconcilable: true,
              calendarData: JSON.parse(row.calendar_data || '{}'),
              driver: 'd1'
            };
          }
          if (row?.status === 'in_flight') {
            return {
              ok: false,
              inFlight: true,
              status: 'in_flight',
              reason: 'REQUEST_IN_FLIGHT',
              driver: 'd1'
            };
          }
        } catch (readErr) {
          console.warn('[D1 Read Error]:', readErr.message);
        }
      }
    }

    // 2. Fallback en Memoria (Driver Local de Pruebas)
    this._cleanup();

    if (this.records.has(key)) {
      const existing = this.records.get(key);

      if (existing.status === 'registered') {
        return {
          ok: false,
          alreadyProcessed: true,
          record: existing,
          driver: 'memory'
        };
      }

      if (existing.status === 'timeout' || existing.status === 'failed_dedupe') {
        return {
          ok: false,
          inFlight: true,
          status: existing.status,
          isReconcilable: true,
          calendarData: existing.calendarData || {},
          record: existing,
          driver: 'memory'
        };
      }

      if (existing.status === 'in_flight') {
        return {
          ok: false,
          inFlight: true,
          status: 'in_flight',
          reason: 'REQUEST_IN_FLIGHT',
          record: existing,
          driver: 'memory'
        };
      }
    }

    // Adquirir lock
    this.records.set(key, {
      leadUid,
      solicitudId,
      status: 'in_flight',
      timestamp: Date.now(),
      expiresAt: Date.now() + (this.defaultTtlSeconds * 1000)
    });

    return { ok: true, driver: 'memory' };
  }

  /**
   * Confirma la solicitud como registrada tras respuesta verificada de Dedupe y Calendar.
   */
  async commit(leadUid, solicitudId, resultData, env) {
    const key = this._getKey(leadUid, solicitudId);
    const record = {
      leadUid,
      solicitudId,
      status: 'registered',
      result: resultData,
      calendarData: resultData?.calendar || {},
      timestamp: Date.now(),
      expiresAt: Date.now() + (this.defaultTtlSeconds * 1000)
    };

    if (env?.DB) {
      try {
        await env.DB.prepare(`
          UPDATE coordinar_idempotencia
          SET status = 'registered', result_json = ?, calendar_data = ?, updated_at = ?
          WHERE lead_uid = ? AND solicitud_id = ?
        `).bind(
          JSON.stringify(resultData),
          JSON.stringify(resultData?.calendar || {}),
          Date.now(),
          leadUid,
          solicitudId
        ).run();
      } catch (err) {
        console.warn('[D1 Commit Error]:', err.message);
      }
    }

    this.records.set(key, record);
  }

  /**
   * Marca como 'timeout' preservando datos de Calendar si se generaron.
   * Evita duplicar el evento Calendar ante reintentos.
   */
  async markTimeout(leadUid, solicitudId, calendarData = {}, errorDetails = {}, env) {
    const key = this._getKey(leadUid, solicitudId);
    const record = {
      leadUid,
      solicitudId,
      status: 'timeout',
      calendarData,
      error: errorDetails,
      timestamp: Date.now(),
      expiresAt: Date.now() + (this.defaultTtlSeconds * 1000)
    };

    if (env?.DB) {
      try {
        await env.DB.prepare(`
          UPDATE coordinar_idempotencia
          SET status = 'timeout', calendar_data = ?, error_details = ?, updated_at = ?
          WHERE lead_uid = ? AND solicitud_id = ?
        `).bind(
          JSON.stringify(calendarData),
          JSON.stringify(errorDetails),
          Date.now(),
          leadUid,
          solicitudId
        ).run();
      } catch (err) {
        // Ignorar
      }
    }

    this.records.set(key, record);
  }

  /**
   * Marca fallo en Dedupe preservando el Calendar ya creado para reconciliación.
   */
  async markFailedDedupe(leadUid, solicitudId, calendarData = {}, env) {
    const key = this._getKey(leadUid, solicitudId);
    const record = {
      leadUid,
      solicitudId,
      status: 'failed_dedupe',
      calendarData,
      timestamp: Date.now(),
      expiresAt: Date.now() + (this.defaultTtlSeconds * 1000)
    };

    if (env?.DB) {
      try {
        await env.DB.prepare(`
          UPDATE coordinar_idempotencia
          SET status = 'failed_dedupe', calendar_data = ?, updated_at = ?
          WHERE lead_uid = ? AND solicitud_id = ?
        `).bind(JSON.stringify(calendarData), Date.now(), leadUid, solicitudId).run();
      } catch (err) {
        // Ignorar
      }
    }

    this.records.set(key, record);
  }

  /**
   * Liberación del lock si el error ocurrió antes de despachar a Make/Calendar.
   */
  async releasePreDispatch(leadUid, solicitudId, env) {
    const key = this._getKey(leadUid, solicitudId);

    if (env?.DB) {
      try {
        await env.DB.prepare(`
          DELETE FROM coordinar_idempotencia
          WHERE lead_uid = ? AND solicitud_id = ? AND status = 'in_flight'
        `).bind(leadUid, solicitudId).run();
      } catch (err) {
        // Ignorar
      }
    }

    this.records.delete(key);
  }

  _cleanup() {
    const now = Date.now();
    for (const [k, rec] of this.records.entries()) {
      if (rec.expiresAt && now > rec.expiresAt) {
        this.records.delete(k);
      }
    }
  }

  clear() {
    this.records.clear();
  }
}

export const robustIdempotencyStore = new RobustIdempotencyStore();
