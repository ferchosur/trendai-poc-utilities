// Página de la demo (port de templates/upload.html de V1_FS_DemoApp_py). Todo texto dinámico se escapa.
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const TITLES = { success: 'Archivo aceptado', scan_error: 'Alerta de File Security', error: 'Archivo no aceptado' };

const CODE_EXAMPLE = `import { readFile } from "node:fs/promises";
import { AmaasGrpcClient } from "file-security-sdk";

const client = new AmaasGrpcClient(
  process.env.V1_REGION,
  process.env.V1_API_KEY,
);
try {
  const fileBytes = await readFile("documento.pdf");
  const result = await client.scanBuffer(
    "documento.pdf", // identificador del archivo
    fileBytes,       // Buffer en memoria
    [],              // tags (máx. 8)
    true,            // pml: machine learning predictivo
  );
  console.log(JSON.stringify(result, null, 2));
} finally {
  client.close();
}`;

export function renderPage({ messages = [], sdkResponse = null } = {}) {
  const notices = messages.length ? `<div class="results" aria-live="polite">${messages.map(([cat, msg]) =>
    `<div class="notice ${cat === 'success' ? 'notice-success' : 'notice-error'}" role="${cat === 'success' ? 'status' : 'alert'}"><strong>${TITLES[cat] ?? TITLES.error}</strong><p>${esc(msg)}</p></div>`).join('')}</div>` : '';
  const has = sdkResponse !== null;
  return `<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#d71920">
    <title>File Security | TrendAI Demo</title>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js" defer></script>
</head>
<body>
    <header class="topbar">
        <a class="brand" href="/" aria-label="TrendAI, inicio"><span class="brand-name">Trend<span>AI</span></span></a>
        <span class="brand-divider" aria-hidden="true"></span>
        <span class="product-name">TrendAI Vision One™</span>
        <span class="demo-badge">DEMO INTERACTIVA</span>
    </header>
    <main>
        <section class="intro">
            <p class="eyebrow">FILE SECURITY / SDK DEMO</p>
            <h1>La seguridad empieza<br>con cada archivo<span>.</span></h1>
            <p class="intro-copy">Analiza archivos antes de incorporarlos a tu aplicación.<br>Experimenta la protección de TrendAI File Security en acción.</p>
            <div class="intro-label"><span aria-hidden="true">↗</span> Integración con File Security SDK</div>
            <div class="orbit" aria-hidden="true"></div>
        </section>
        <div class="workspace">
            <section class="upload-card" aria-labelledby="upload-title">
                <div class="card-heading"><div><p class="eyebrow">ANÁLISIS DE ARCHIVOS</p><h2 id="upload-title">Carga. Analiza. Protege.</h2></div><span class="step-tag">01 / CARGA</span></div>
                <p class="card-description">Selecciona un archivo para enviarlo al servicio de análisis.</p>
                ${notices}
                <form method="post" enctype="multipart/form-data" id="upload-form">
                    <div class="drop-zone" id="drop-zone">
                        <svg class="upload-icon" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M16 33H12a8 8 0 0 1-1-16 13 13 0 0 1 25-2 9 9 0 0 1 0 18h-4M24 38V20m-7 7 7-7 7 7"/></svg>
                        <label for="file" class="file-label">Arrastra tu archivo aquí</label>
                        <p>o selecciónalo desde tu equipo</p>
                        <input type="file" id="file" name="file" accept=".txt,.pdf,.png,.jpg,.jpeg,.gif" aria-describedby="file-hint client-error" required>
                        <span id="file-hint" class="file-hint">TXT, PDF, PNG, JPG, JPEG y GIF · Solicitud máxima: 16 MiB</span>
                    </div>
                    <div class="file-summary" id="file-summary" hidden><span class="file-type" aria-hidden="true">FILE</span><div><strong id="file-name"></strong><span id="file-size"></span></div><button type="button" id="clear-file" aria-label="Quitar archivo">×</button></div>
                    <p id="client-error" class="client-error" role="alert" hidden></p>
                    <button class="scan-button" id="scan-button" type="submit"><span id="button-label">Analizar archivo</span><span id="button-icon" aria-hidden="true">→</span></button>
                    <p class="scan-status" id="scan-status" role="status" hidden>Enviando archivo y esperando el resultado del análisis…</p>
                    <p class="privacy-note">El archivo se envía a File Security para su análisis.</p>
                </form>
            </section>
            <aside class="integration-panel" aria-label="Integración y respuesta del SDK">
                <section class="developer-card" aria-labelledby="code-title">
                    <div class="developer-heading"><div><p class="eyebrow">INTEGRA FILE SECURITY</p><h2 id="code-title">De tu app al SDK.</h2></div><span class="language-badge">NODE.JS</span></div>
                    <p class="card-description">El mismo flujo de escaneo que utiliza esta demo.</p>
                    <button type="button" class="code-toggle" id="code-toggle" aria-expanded="false" aria-controls="integration-code">Mostrar ejemplo de código</button>
                    <div id="integration-code" hidden>
                    <pre class="code-example" tabindex="0" aria-label="Ejemplo de integración Node.js"><code>${esc(CODE_EXAMPLE)}</code></pre>
                    <p class="code-caption">Credenciales en variables de entorno. La respuesta JSON contiene el resultado del análisis.</p>
                    </div>
                </section>
                <section class="developer-card response-card" aria-labelledby="response-title">
                    <div class="developer-heading"><div><p class="eyebrow">RESULTADO DEL SERVICIO</p><h2 id="response-title">Respuesta del SDK</h2></div><span class="language-badge">JSON</span></div>
                    <p class="card-description" id="response-help">${has ? 'Respuesta del último intento en esta página.' : 'Analiza un archivo para ver aquí la respuesta real del servicio.'}</p>
                    <label class="sr-only" for="sdk-response">Respuesta JSON de File Security</label>
                    <textarea id="sdk-response" class="sdk-response" readonly spellcheck="false" aria-describedby="response-help" placeholder="La respuesta del SDK aparecerá aquí después del análisis.">${has ? esc(sdkResponse) : ''}</textarea>
                    <p class="code-caption">${has ? 'Las respuestas del servicio se muestran completas. Si la llamada falla sin respuesta, se muestra un error de la aplicación.' : 'Sin datos simulados. Se actualiza al completar cada intento.'}</p>
                </section>
                <div class="demo-note"><span class="note-label">ENTORNO DE DEMOSTRACIÓN</span><p>Los archivos aceptados permanecen en el servidor. Utiliza archivos de prueba sin información sensible.</p></div>
            </aside>
        </div>
    </main>
    <footer><span>TrendAI <span class="footer-dot">/</span> File Security</span><span>SDK Demo · Node.js</span></footer>
</body>
</html>`;
}
