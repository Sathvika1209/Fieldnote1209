import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { extname, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const { Pool } = pg;
const required = ['JWT_SECRET', 'DATABASE_URL', 'AWS_REGION', 'S3_BUCKET'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters.');
const maxFileBytes = Number(process.env.MAX_FILE_BYTES || 104857600);
const pgSsl = process.env.PGSSL === 'true'
  ? { rejectUnauthorized: true, ...(process.env.PGSSLROOTCERT ? { ca: readFileSync(process.env.PGSSLROOTCERT, 'utf8') } : {}) }
  : undefined;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: pgSsl });
const s3 = new S3Client({ region: process.env.AWS_REGION });
const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));

const sign = student => jwt.sign({ sub: student.id }, process.env.JWT_SECRET, { expiresIn: '12h', issuer: 'fieldnote' });
function auth(req, res, next) {
  const token = req.get('authorization')?.match(/^Bearer (.+)$/i)?.[1];
  if (!token) return res.status(401).json({ error: 'Sign in to continue.' });
  try { req.studentId = jwt.verify(token, process.env.JWT_SECRET, { issuer: 'fieldnote' }).sub; next(); }
  catch { return res.status(401).json({ error: 'Your session expired. Sign in again.' }); }
}
const normalize = row => ({ id: row.id, name: row.name, size: Number(row.size_bytes), type: row.content_type, folder: row.folder, modified: new Date(row.updated_at).getTime(), starred: row.starred });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, mode: 'aws', maxFileBytes });
}));
app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10) return res.status(400).json({ error: 'Enter a valid email and a password of at least 10 characters.' });
  const displayName = email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()).slice(0, 80);
  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await pool.query('INSERT INTO students(email, display_name, password_hash) VALUES($1,$2,$3) RETURNING id,email,display_name', [email, displayName, hash]);
    res.status(201).json({ token: sign(rows[0]), student: { id: rows[0].id, email, name: rows[0].display_name } });
  } catch (err) { if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists. Sign in instead.' }); throw err; }
}));
app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const { rows } = await pool.query('SELECT id,email,display_name,password_hash FROM students WHERE email=$1', [email]);
  if (!rows.length || !await bcrypt.compare(String(req.body.password || ''), rows[0].password_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  res.json({ token: sign(rows[0]), student: { id: rows[0].id, email, name: rows[0].display_name } });
}));
app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT id,email,display_name FROM students WHERE id=$1', [req.studentId]);
  if (!rows.length) return res.status(401).json({ error: 'Account not found.' });
  res.json({ id: rows[0].id, email: rows[0].email, name: rows[0].display_name });
}));
app.get('/api/files', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT id,name,content_type,size_bytes,folder,starred,updated_at FROM backed_up_files WHERE student_id=$1 ORDER BY updated_at DESC', [req.studentId]);
  res.json(rows.map(normalize));
}));
app.post('/api/files/upload-url', auth, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 255);
  const size = Number(req.body.size);
  const type = String(req.body.type || 'application/octet-stream').slice(0, 160);
  if (!name || !Number.isSafeInteger(size) || size < 0 || size > maxFileBytes) return res.status(400).json({ error: `Choose a file smaller than ${Math.floor(maxFileBytes / 1048576)} MB.` });
  const { rows: usage } = await pool.query('SELECT COALESCE(SUM(size_bytes),0) AS used FROM backed_up_files WHERE student_id=$1', [req.studentId]);
  if (Number(usage[0].used) + size > 2 * 1024 * 1024 * 1024) return res.status(413).json({ error: 'Your 2 GB workspace storage limit has been reached.' });
  const id = randomUUID(), key = `students/${req.studentId}/${id}${extname(name).slice(0, 16)}`;
  const folder = ['Projects', 'Research', 'Design', 'Other'].includes(req.body.folder) ? req.body.folder : 'Projects';
  const command = new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key, ContentType: type, ContentLength: size, ServerSideEncryption: 'AES256' });
  const url = await getSignedUrl(s3, command, { expiresIn: 300 });
  res.json({ id, key, url, method: 'PUT', headers: { 'Content-Type': type, 'x-amz-server-side-encryption': 'AES256' }, name, size, type, folder });
}));
app.post('/api/files/commit', auth, asyncRoute(async (req, res) => {
  const { id, key, name, size, type, folder } = req.body;
  if (typeof id !== 'string' || typeof key !== 'string' || !key.startsWith(`students/${req.studentId}/`)) return res.status(400).json({ error: 'Invalid upload reference.' });
  const head = await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key }));
  if (Number(head.ContentLength) !== Number(size)) return res.status(400).json({ error: 'Uploaded file size did not match.' });
  const { rows } = await pool.query('INSERT INTO backed_up_files(id,student_id,name,content_type,size_bytes,folder,s3_key) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,content_type,size_bytes,folder,starred,updated_at', [id, req.studentId, String(name).slice(0, 255), String(type || 'application/octet-stream').slice(0, 160), Number(size), ['Projects', 'Research', 'Design', 'Other'].includes(folder) ? folder : 'Projects', key]);
  res.status(201).json(normalize(rows[0]));
}));
app.get('/api/files/:id/download', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query('SELECT s3_key,name,content_type FROM backed_up_files WHERE id=$1 AND student_id=$2', [req.params.id, req.studentId]);
  if (!rows.length) return res.status(404).json({ error: 'File not found.' });
  const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: rows[0].s3_key, ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(rows[0].name)}` }), { expiresIn: 300 });
  res.json({ url });
}));
app.patch('/api/files/:id', auth, asyncRoute(async (req, res) => {
  const allowed = {};
  if (typeof req.body.starred === 'boolean') allowed.starred = req.body.starred;
  if (['Projects', 'Research', 'Design', 'Other'].includes(req.body.folder)) allowed.folder = req.body.folder;
  if (!Object.keys(allowed).length) return res.status(400).json({ error: 'No supported file changes provided.' });
  const { rows } = await pool.query('UPDATE backed_up_files SET starred=COALESCE($3,starred), folder=COALESCE($4,folder), updated_at=now() WHERE id=$1 AND student_id=$2 RETURNING id,name,content_type,size_bytes,folder,starred,updated_at', [req.params.id, req.studentId, allowed.starred ?? null, allowed.folder ?? null]);
  if (!rows.length) return res.status(404).json({ error: 'File not found.' });
  res.json(normalize(rows[0]));
}));
app.delete('/api/files/:id', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query('DELETE FROM backed_up_files WHERE id=$1 AND student_id=$2 RETURNING s3_key', [req.params.id, req.studentId]);
  if (!rows.length) return res.status(404).json({ error: 'File not found.' });
  await s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET, Key: rows[0].s3_key }));
  res.status(204).end();
}));

app.use(express.static(join(dirname(fileURLToPath(import.meta.url)), 'public')));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Something went wrong. Please try again.' }); });
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Fieldnote listening on port ${port}`));
process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
