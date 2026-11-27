// File Security SDK Demo (Node.js). Port de V1_FS_DemoApp_py (Flask) a Express.
import express from 'express';
import multer from 'multer';
import { mkdirSync } from 'node:fs';
import { writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { malwareScan, ScanFailure } from './scan.js';
import { renderPage } from './views.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const UPLOAD_FOLDER = process.env.UPLOAD_FOLDER || 'uploads';
const MAX_BYTES = 16 * 1024 * 1024;
const ALLOWED = new Set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']);
mkdirSync(UPLOAD_FOLDER, { recursive: true });

// Nombre seguro (equivalente a secure_filename de Werkzeug).
export function secureFilename(name) {
  return path.basename(String(name)).normalize('NFKD').replace(/[^\x20-\x7e]/g, '')
    .replace(/\s+/g, '_').replace(/[^A-Za-z0-9_.-]/g, '').replace(/^[._]+|[._]+$/g, '');
}
const allowedFile = name => name.includes('.') && ALLOWED.has(name.split('.').pop().toLowerCase());

export const app = express();
app.disable('x-powered-by');
app.use('/static', express.static(path.join(here, 'public')));

// El archivo queda en memoria: nunca se escribe a disco antes del escaneo.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_BYTES, files: 1 } });

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/ready', (req, res) => res.json({ status: 'ready' }));
app.get('/', (req, res) => res.send(renderPage()));

app.post('/', (req, res) => {
  upload.single('file')(req, res, async err => {
    const page = (messages, sdkResponse = null, status = 200) => res.status(status).send(renderPage({ messages, sdkResponse }));
    if (err?.code === 'LIMIT_FILE_SIZE') return page([['error', 'El archivo supera el máximo de 16 MiB.']], null, 413);
    if (err) return page([['error', `Error al procesar el archivo: ${err.message}`]]);
    if (!req.file?.originalname) return page([['error', 'Selecciona un archivo para iniciar el análisis.']]);
    if (!allowedFile(req.file.originalname)) return page([['error', 'Tipo de archivo no permitido']]);

    const filename = secureFilename(req.file.originalname) || 'archivo';
    let tmpPath;
    try {
      const { accepted, response } = await malwareScan(req.file.buffer, filename);
      const sdkResponse = JSON.stringify(response, null, 2);
      if (!accepted) return page([['error', `Archivo ${filename} es malicioso`]], sdkResponse);
      // Solo los archivos aceptados se escriben: temporal + rename atómico.
      tmpPath = path.join(UPLOAD_FOLDER, `.tmp-${randomBytes(8).toString('hex')}${path.extname(filename)}`);
      await writeFile(tmpPath, req.file.buffer, { flag: 'wx' });
      await rename(tmpPath, path.join(UPLOAD_FOLDER, filename));
      tmpPath = undefined;
      return page([['success', `Archivo ${filename} subido exitosamente`]], sdkResponse);
    } catch (error) {
      if (error instanceof ScanFailure)
        return page([['scan_error', error.message]], JSON.stringify({ error: error.message }, null, 2));
      console.error('Failed to process or save uploaded file', error);
      return page([['error', `Error al procesar el archivo: ${error.message}`]]);
    } finally {
      if (tmpPath) await rm(tmpPath, { force: true }).catch(e => console.warn('Could not remove upload temporary file', e));
    }
  });
});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8080);
  app.listen(port, '0.0.0.0', () => console.log(`File Security demo (Node.js) en http://localhost:${port}`));
}
