// Integración con Vision One File Security (SDK Node.js `file-security-sdk`).
// Equivale a malware_scan / scan_is_clean / api_key_alert de la demo Python.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { AmaasGrpcClient } from 'file-security-sdk';

const SDK_VERSION = createRequire(import.meta.url)('file-security-sdk/package.json').version;

export class ScanFailure extends Error {}

// Lee los dos formatos de respuesta; rechaza detecciones, errores y datos desconocidos.
export function scanIsClean(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return false;
  if (![null, undefined, 0].includes(result.scanResult)) return false;
  if (result.foundMalwares?.length || result.foundErrors?.length || result.error) return false;
  if ('result' in result) {
    const engines = result.result;
    if (!engines || typeof engines !== 'object' || !Object.keys(engines).length) return false;
    return Object.values(engines).every(e =>
      e && typeof e === 'object' && Number.isInteger(e.malwareCount) && e.malwareCount === 0 && !e.malware?.length && !e.error);
  }
  return 'scanResult' in result && [null, 0].includes(result.scanResult);
}

// El SDK de Node no expone el código gRPC: se identifica por el texto del mensaje (README del SDK).
export function apiKeyAlert(error) {
  const msg = String(error?.message ?? '');
  if (!process.env.V1_API_KEY) return 'Falta la API key de File Security. Configura V1_API_KEY y reinicia la app.';
  if (msg.startsWith('You are not authenticated'))
    return 'File Security rechazó la API key. Puede ser inválida, haber expirado o no tener permisos. ' +
      'Revisa la clave, la región y el permiso Run file scan via SDK.';
  if (msg.startsWith('You do not have sufficient permissions'))
    return 'File Security denegó el acceso (PERMISSION_DENIED). Revisa los permisos de la API key y el acceso a File Security.';
  return null;
}

const log = (level, event) => console[level](JSON.stringify(event));

// Escanea bytes en memoria. Devuelve { accepted, response } o lanza ScanFailure con un mensaje seguro.
export async function malwareScan(content, fileName, { createClient = (r, k) => new AmaasGrpcClient(r, k) } = {}) {
  const correlationId = randomUUID().replaceAll('-', '');
  const started = performance.now();
  let client;
  let response;
  try {
    if (!process.env.V1_API_KEY) throw new Error('missing api key');
    client = createClient(process.env.V1_REGION, process.env.V1_API_KEY);
    response = await client.scanBuffer(fileName, content, [], true); // pml = true
    log('info', {
      event: 'filesecurity.scan.response', correlation_id: correlationId, sdk_version: SDK_VERSION,
      file_name: fileName, elapsed_ms: Math.round((performance.now() - started) * 100) / 100,
      sdk_response: JSON.stringify(response),
    });
    const accepted = scanIsClean(response);
    log('info', { event: 'filesecurity.scan.decision', correlation_id: correlationId, accepted });
    return { accepted, response };
  } catch (error) {
    const alert = apiKeyAlert(error);
    if (alert) {
      log('warn', { event: 'filesecurity.api_key.alert', correlation_id: correlationId, message: alert });
      throw new ScanFailure(`${alert} Referencia: ${correlationId}`);
    }
    console.error(`File Security scan failed correlation_id=${correlationId}`, error);
    // Visto con SDK 1.4.8 y una key inválida: a veces llega "You are not authenticated" y a veces "Service is not reachable"
    // (el SDK resolvió otro host). Se cubren ambos casos.
    if (String(error?.message).startsWith('Service is not reachable'))
      throw new ScanFailure('No se pudo conectar con File Security. Revisa la red, V1_REGION y que V1_API_KEY sea una API key ' +
        `de Vision One completa y vigente. Referencia: ${correlationId}`);
    throw new ScanFailure(`No se pudo completar el análisis de File Security. Revisa los logs. Referencia: ${correlationId}`);
  } finally {
    try { client?.close(); } catch (e) { console.error(`File Security cleanup failed correlation_id=${correlationId}`, e); }
  }
}
