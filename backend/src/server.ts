import './config/env.ts';
import * as http from 'http';
import * as crypto from 'crypto';
import _sodium from 'libsodium-wrappers';
import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { pipeline } from 'stream/promises';
import { Busboy } from '@fastify/busboy';
import * as yauzl from 'yauzl';

import { NodeRegistry } from './nodes/registry.ts';
import { WorkflowEngine } from './engine/workflow-engine.ts';
import { TemplateCatalog } from './templates/catalog.ts';
import { CiCdManager } from './cicd/index.ts';
import { AiWorkflowGenerator } from './ai/workflow-generator.ts';
import { db, type UserProfile } from './storage/db.ts';
import { SecretVault } from './storage/crypto.ts';
import { WorkflowScheduler, CronParser } from './engine/scheduler.ts';
import { sendYandexMail } from './notifications/mailer.ts';
import type { WorkflowGraph, WorkflowExecutionEvent } from './engine/types.ts';
import { extractWorkflowFindings } from './engine/workflow-utils.ts';
import { isPrivateOrLoopbackUrl } from './validators/ssrf-validator.ts';
import { maskSensitiveText, sanitizeFindingForExport } from './validators/submission-validator.ts';
import { exportToSarif } from './exporters/sarif.ts';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;

export function getPublicBaseUrl(req?: http.IncomingMessage): string {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  }
  if (req && req.headers) {
    const proto = (req.headers['x-forwarded-proto'] as string) || 'http';
    const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
    return `${proto}://${host}`;
  }
  return `http://localhost:${PORT}`;
}

const registry = new NodeRegistry();
const engine = new WorkflowEngine(registry);
const templates = new TemplateCatalog();
const scheduler = new WorkflowScheduler(engine, templates, db, (event) => broadcastEvent(event));

// In-memory run history (kept in sync with PostgreSQL)
const runHistory: any[] = [];

// SSE client connections for real-time live events
const sseClients = new Set<http.ServerResponse>();

const server = http.createServer(async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', getPublicBaseUrl(req));
  const pathname = url.pathname;

  try {
    // Serve Web UI Frontend & Static Assets (with strict Path Traversal protection)
    if ((req.method === 'GET' || req.method === 'HEAD') && (pathname === '/' || !pathname.startsWith('/api/'))) {
      let decodedPath = '';
      try {
        decodedPath = decodeURIComponent(pathname);
      } catch {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Bad Request');
        return;
      }

      // Block path traversal sequences
      if (decodedPath.includes('..') || decodedPath.includes('\\')) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden: Path traversal sequence blocked');
        return;
      }

      const publicDir = path.resolve(process.cwd(), 'backend', 'public');
      const targetRelPath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
      const filePath = path.resolve(publicDir, targetRelPath);

      if (filePath.startsWith(publicDir) && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes: Record<string, string> = {
          '.html': 'text/html; charset=utf-8',
          '.css': 'text/css; charset=utf-8',
          '.js': 'application/javascript; charset=utf-8',
          '.json': 'application/json; charset=utf-8',
          '.svg': 'image/svg+xml',
          '.png': 'image/png'
        };
        res.writeHead(200, {
          'Content-Type': mimeTypes[ext] || 'application/octet-stream',
          'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        if (req.method === 'HEAD') {
          res.end();
          return;
        }
        res.end(fs.readFileSync(filePath));
        return;
      }
    }

    // Real-time Server-Sent Events (SSE) Stream
    if (req.method === 'GET' && (pathname === '/api/events' || pathname === '/api/workflow/stream')) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });
      res.write(`data: ${JSON.stringify({ type: 'connected', message: 'SSE Stream Active' })}\n\n`);

      sseClients.add(res);
      req.on('close', () => {
        sseClients.delete(res);
      });
      return;
    }

    // =========================================================================
    // AUTHENTICATION & USER PROFILES (GitHub & GitVerse Integration)
    // =========================================================================

    if (req.method === 'POST' && pathname === '/api/sources/local-archive') {
      const user = await getUserFromRequest(req);
      const uploadRoot = path.resolve(process.cwd(), 'uploads', randomUUID());
      const archivePath = `${uploadRoot}.zip`;
      const maxFiles = 1000;
      const maxFileSize = 20 * 1024 * 1024;
      const maxTotalSize = 100 * 1024 * 1024;
      const maxArchiveSize = 100 * 1024 * 1024;
      let uploadError: Error | undefined;
      let archiveReceived = false;
      let archiveWrite: Promise<void> | undefined;

      try {
        await fs.promises.mkdir(uploadRoot, { recursive: true });
        const parser = Busboy({
          headers: req.headers as { 'content-type': string },
          limits: { files: 1, fileSize: maxArchiveSize, fields: 0, parts: 1 }
        });

        parser.on('file', (fieldName, file, filename) => {
          if (fieldName !== 'archive' || !filename.toLowerCase().endsWith('.zip') || archiveReceived) {
            uploadError ??= new Error('Можно загрузить только один ZIP-архив.');
            file.resume();
            return;
          }

          archiveReceived = true;
          archiveWrite = pipeline(file, fs.createWriteStream(archivePath, { flags: 'wx' }))
            .then(() => {
              if (file.truncated) {
                throw new Error('Размер ZIP-архива превышает ограничение 100 МБ.');
              }
            })
            .catch((err: Error) => {
              uploadError ??= err;
            });
        });

        parser.on('field', () => {
          uploadError ??= new Error('Запрос должен содержать только один ZIP-архив.');
        });
        parser.on('filesLimit', () => uploadError ??= new Error('Можно загрузить только один ZIP-архив.'));

        await new Promise<void>((resolve, reject) => {
          parser.once('error', reject);
          parser.once('finish', resolve);
          req.once('error', reject);
          req.pipe(parser);
        });
        await archiveWrite;

        if (uploadError) throw uploadError;
        if (!archiveReceived) {
          throw new Error('Выберите ZIP-архив для загрузки.');
        }

        const signature = Buffer.alloc(4);
        const archiveHandle = await fs.promises.open(archivePath, 'r');
        try {
          await archiveHandle.read(signature, 0, signature.length, 0);
        } finally {
          await archiveHandle.close();
        }
        if (signature[0] !== 0x50 || signature[1] !== 0x4b) {
          throw new Error('Файл не является корректным ZIP-архивом.');
        }

        let fileCount = 0;
        let totalBytes = 0;
        const zipFile = await new Promise<yauzl.ZipFile>((resolve, reject) => {
          yauzl.open(archivePath, { lazyEntries: true, autoClose: false }, (err, zip) => {
            if (err || !zip) reject(err || new Error('Не удалось открыть ZIP-архив.'));
            else resolve(zip);
          });
        });

        await new Promise<void>((resolve, reject) => {
          let settled = false;
          const fail = (err: Error) => {
            if (settled) return;
            settled = true;
            zipFile.close();
            reject(err);
          };

          zipFile.on('error', fail);
          zipFile.on('end', () => {
            if (settled) return;
            settled = true;
            zipFile.close();
            resolve();
          });
          zipFile.on('entry', entry => {
            void (async () => {
              const isDirectory = entry.fileName.endsWith('/');
              const entryName = entry.fileName.replace(/\\/g, '/').replace(/\/+$/, '');
              const pathParts: string[] = entryName.split('/');
              const mode = (entry.externalFileAttributes >>> 16) & 0xf000;
              if (
                !entryName ||
                entryName.startsWith('/') ||
                /^[a-zA-Z]:/.test(entryName) ||
                pathParts.some(part => !part || part === '.' || part === '..') ||
                (mode !== 0 && mode !== 0x8000 && mode !== 0x4000) ||
                (isDirectory && mode === 0x8000) ||
                (!isDirectory && mode === 0x4000)
              ) {
                throw new Error('В ZIP-архиве обнаружен недопустимый путь или тип файла.');
              }

              const destination = path.resolve(uploadRoot, ...pathParts);
              const relativePath = path.relative(uploadRoot, destination);
              if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
                throw new Error('Путь в ZIP-архиве выходит за пределы проекта.');
              }

              if (isDirectory) {
                await fs.promises.mkdir(destination, { recursive: true });
                zipFile.readEntry();
                return;
              }

              fileCount += 1;
              if (fileCount > maxFiles) {
                throw new Error('В архиве слишком много файлов (максимум 1000).');
              }
              if (entry.uncompressedSize > maxFileSize) {
                throw new Error('Размер одного из файлов в архиве превышает ограничение 20 МБ.');
              }
              totalBytes += entry.uncompressedSize;
              if (totalBytes > maxTotalSize) {
                throw new Error('Общий размер файлов в архиве превышает ограничение 100 МБ.');
              }

              await fs.promises.mkdir(path.dirname(destination), { recursive: true });
              await new Promise<void>((streamResolve, streamReject) => {
                zipFile.openReadStream(entry, (err, readStream) => {
                  if (err || !readStream) {
                    streamReject(err || new Error('Не удалось прочитать файл из ZIP-архива.'));
                    return;
                  }
                  pipeline(readStream, fs.createWriteStream(destination, { flags: 'wx' }))
                    .then(() => streamResolve(), streamReject);
                });
              });
              zipFile.readEntry();
            })().catch(fail);
          });
          zipFile.readEntry();
        });

        if (fileCount === 0) {
          throw new Error('В ZIP-архиве не найдены файлы проекта.');
        }
        await fs.promises.rm(archivePath, { force: true });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          path: uploadRoot,
          fileCount,
          totalBytes
        }));
      } catch (err: any) {
        await fs.promises.rm(uploadRoot, { recursive: true, force: true });
        await fs.promises.rm(archivePath, { force: true });
        const message = err?.message || 'Не удалось загрузить ZIP-архив проекта.';
        const statusCode = /превышает ограничение|слишком много файлов/i.test(message) ? 413 : 400;
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: message }));
      }
      return;
    }

    // POST /api/auth/register
    if (req.method === 'POST' && pathname === '/api/auth/register') {
      const body = await parseJsonBody(req);
      const email = (body.email || '').trim().toLowerCase();
      const password = body.password || '';
      const name = (body.name || '').trim() || email.split('@')[0];

      if (!email || !email.includes('@')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Укажите корректный email адрес' }));
        return;
      }
      if (!password || password.length < 4) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Пароль должен содержать не менее 4 символов' }));
        return;
      }

      const existing = await db.getUserByEmail(email);
      if (existing) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Пользователь с таким email уже зарегистрирован' }));
        return;
      }

      const passwordHash = SecretVault.hashPassword(password);
      const user = await db.createUser({
        id: 'usr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
        email,
        passwordHash,
        name,
        avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`
      });

      const token = await db.createSession(user.id);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, token, user: sanitizeUser(user) }));
      return;
    }

    // POST /api/auth/login
    if (req.method === 'POST' && pathname === '/api/auth/login') {
      const body = await parseJsonBody(req);
      const email = (body.email || '').trim().toLowerCase();
      const password = body.password || '';

      let user = await db.getUserByEmail(email);
      if (!user && (email === 'test' || email === 'test@uncflow.local' || email === 'test@uncflow.io')) {
        user = await db.getUserById('user_test');
      }
      if (!user || !user.passwordHash || !SecretVault.verifyPassword(password, user.passwordHash)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Неверный логин или пароль. Для показа на защите войдите как test / test' }));
        return;
      }

      const token = await db.createSession(user.id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, token, user: sanitizeUser(user) }));
      return;
    }

    // POST /api/auth/github-token (Direct login or link with GitHub Personal Access Token)
    if (req.method === 'POST' && pathname === '/api/auth/github-token') {
      const body = await parseJsonBody(req);
      const token = (body.token || '').trim();
      if (!token) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'GitHub токен обязателен' }));
        return;
      }

      try {
        const ghRes = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'User-Agent': 'uncflow-AppSec',
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        if (!ghRes.ok) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Неверный токен GitHub или токен истек' }));
          return;
        }
        const ghUser = await ghRes.json();
        const currentUser = await getUserFromRequest(req);

        let targetUser: UserProfile;
        if (currentUser) {
          // Link to currently authenticated user profile
          targetUser = (await db.updateUserProfile(currentUser.id, {
            githubId: String(ghUser.id),
            githubUsername: ghUser.login,
            githubToken: token,
            avatarUrl: currentUser.avatarUrl || ghUser.avatar_url
          }))!;
        } else {
          // Find by github_id or email, or create
          let existing = await db.getUserByGithubId(String(ghUser.id));
          if (!existing && ghUser.email) {
            existing = await db.getUserByEmail(ghUser.email);
          }

          if (existing) {
            targetUser = (await db.updateUserProfile(existing.id, {
              githubId: String(ghUser.id),
              githubUsername: ghUser.login,
              githubToken: token,
              avatarUrl: ghUser.avatar_url || existing.avatarUrl
            }))!;
          } else {
            const email = ghUser.email || `${ghUser.login}@users.noreply.github.com`;
            targetUser = await db.createUser({
              id: 'usr_gh_' + ghUser.id,
              email,
              name: ghUser.name || ghUser.login,
              avatarUrl: ghUser.avatar_url,
              githubId: String(ghUser.id),
              githubUsername: ghUser.login,
              githubToken: token
            });
          }
        }

        const sessionToken = await db.createSession(targetUser.id);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, token: sessionToken, user: sanitizeUser(targetUser) }));
        return;
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Ошибка проверки GitHub токена: ${err.message}` }));
        return;
      }
    }

    // GET /api/auth/github (OAuth Start)
    if (req.method === 'GET' && pathname === '/api/auth/github') {
      const clientId = process.env.GITHUB_CLIENT_ID;
      if (!clientId) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          configured: false,
          message: 'GitHub OAuth Client ID не задан в переменных окружения. Используйте вход по Personal Access Token (PAT).'
        }));
        return;
      }
      const redirectUri = encodeURIComponent(`${getPublicBaseUrl(req)}/api/auth/github/callback`);
      const ghAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=repo,workflow,read:user,user:email`;
      res.writeHead(302, { 'Location': ghAuthUrl });
      res.end();
      return;
    }

    // GET /api/auth/github/callback (OAuth Callback)
    if (req.method === 'GET' && pathname === '/api/auth/github/callback') {
      const code = url.searchParams.get('code');
      const ghError = url.searchParams.get('error_description') || url.searchParams.get('error');
      const clientId = process.env.GITHUB_CLIENT_ID;
      const clientSecret = process.env.GITHUB_CLIENT_SECRET;

      if (ghError) {
        res.writeHead(302, { 'Location': '/?auth_error=' + encodeURIComponent(ghError) });
        res.end();
        return;
      }

      if (!clientId || !clientSecret) {
        res.writeHead(302, { 'Location': '/?auth_error=' + encodeURIComponent('Отсутствуют параметры GitHub OAuth Client ID или Client Secret на сервере') });
        res.end();
        return;
      }

      if (!code) {
        res.writeHead(302, { 'Location': '/?auth_error=' + encodeURIComponent('Код авторизации не получен от GitHub') });
        res.end();
        return;
      }

      try {
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            client_id: clientId,
            client_secret: clientSecret,
            code
          })
        });
        const tokenData = await tokenRes.json();
        const accessToken = tokenData.access_token;
        if (!accessToken) {
          res.writeHead(302, { 'Location': '/?auth_error=' + encodeURIComponent(tokenData.error_description || 'Ошибка получения токена GitHub') });
          res.end();
          return;
        }

        const ghUserRes = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'User-Agent': 'uncflow-AppSec'
          }
        });
        const ghUser = await ghUserRes.json();

        let existing = await db.getUserByGithubId(String(ghUser.id));
        if (!existing && ghUser.email) {
          existing = await db.getUserByEmail(ghUser.email);
        }

        let user: UserProfile;
        if (existing) {
          user = (await db.updateUserProfile(existing.id, {
            githubId: String(ghUser.id),
            githubUsername: ghUser.login,
            githubToken: accessToken,
            avatarUrl: ghUser.avatar_url || existing.avatarUrl
          }))!;
        } else {
          user = await db.createUser({
            id: 'usr_gh_' + ghUser.id,
            email: ghUser.email || `${ghUser.login}@users.noreply.github.com`,
            name: ghUser.name || ghUser.login,
            avatarUrl: ghUser.avatar_url,
            githubId: String(ghUser.id),
            githubUsername: ghUser.login,
            githubToken: accessToken
          });
        }

        const sessionToken = await db.createSession(user.id);
        res.writeHead(302, { 'Location': `/?auth_token=${sessionToken}` });
        res.end();
        return;
      } catch (err: any) {
        res.writeHead(302, { 'Location': '/?auth_error=' + encodeURIComponent(err.message) });
        res.end();
        return;
      }
    }

    // GET /api/auth/me (Current user info)
    if (req.method === 'GET' && pathname === '/api/auth/me') {
      const user = await getUserFromRequest(req);
      if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Не авторизован', authenticated: false }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ authenticated: true, user: sanitizeUser(user) }));
      return;
    }

    // PUT /api/auth/profile (Update profile: name, email, GitHub token, GitVerse token)
    if (req.method === 'PUT' && pathname === '/api/auth/profile') {
      const user = await getUserFromRequest(req);
      if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Необходима авторизация' }));
        return;
      }

      const body = await parseJsonBody(req);
      const updates: Partial<UserProfile> = {};
      if (body.name !== undefined) updates.name = body.name.trim();
      if (body.email !== undefined && body.email.includes('@')) updates.email = body.email.trim().toLowerCase();
      if (body.gitverseUsername !== undefined) updates.gitverseUsername = body.gitverseUsername.trim();
      if (body.gitverseToken !== undefined) updates.gitverseToken = body.gitverseToken.trim();
      if (body.gigachatCredentials !== undefined) updates.gigachatCredentials = body.gigachatCredentials.trim();
      if (body.gigachatScope !== undefined) updates.gigachatScope = body.gigachatScope.trim();
      if (body.telegramBotToken !== undefined) updates.telegramBotToken = body.telegramBotToken.trim();
      if (body.telegramChatId !== undefined) updates.telegramChatId = body.telegramChatId.trim();
      if (body.yandexMailUser !== undefined) updates.yandexMailUser = body.yandexMailUser.trim();
      if (body.yandexMailPassword !== undefined) updates.yandexMailPassword = body.yandexMailPassword.trim();
      if (body.yandexMailTo !== undefined) updates.yandexMailTo = body.yandexMailTo.trim();
      if (body.webhookUrl !== undefined) updates.webhookUrl = body.webhookUrl.trim();
      if (body.webhookSecret !== undefined) updates.webhookSecret = body.webhookSecret.trim();
      if (body.githubToken !== undefined) {
        const ghToken = body.githubToken.trim();
        updates.githubToken = ghToken;
        if (ghToken) {
          try {
            const ghRes = await fetch('https://api.github.com/user', {
              headers: { 'Authorization': `Bearer ${ghToken}`, 'User-Agent': 'uncflow-AppSec' }
            });
            if (ghRes.ok) {
              const ghData = await ghRes.json();
              updates.githubId = String(ghData.id);
              updates.githubUsername = ghData.login;
              if (ghData.avatar_url && !user.avatarUrl) updates.avatarUrl = ghData.avatar_url;
            }
          } catch {}
        }
      }

      const updated = await db.updateUserProfile(user.id, updates);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, user: sanitizeUser(updated || user) }));
      return;
    }

    // POST /api/auth/logout
    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : '';
      if (token) {
        await db.deleteSession(token);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Сессия завершена' }));
      return;
    }

    // GET /api/auth/github/repos (Fetch user's private and public repositories)
    if (req.method === 'GET' && pathname === '/api/auth/github/repos') {
      const user = await getUserFromRequest(req);
      if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Необходима авторизация' }));
        return;
      }
      if (!user.githubToken) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'GitHub токен не привязан к профилю. Укажите токен в настройках профиля.' }));
        return;
      }

      try {
        const ghRes = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated', {
          headers: {
            'Authorization': `Bearer ${user.githubToken}`,
            'User-Agent': 'uncflow-AppSec',
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        if (!ghRes.ok) {
          const ghErr = await ghRes.text();
          res.writeHead(ghRes.status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `GitHub API error: ${ghErr}` }));
          return;
        }
        const repos = await ghRes.json();
        const mappedRepos = (Array.isArray(repos) ? repos : []).map((r: any) => ({
          id: r.id,
          name: r.name,
          fullName: r.full_name,
          private: r.private,
          htmlUrl: r.html_url,
          cloneUrl: r.clone_url,
          defaultBranch: r.default_branch || 'main',
          description: r.description
        }));

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ repos: mappedRepos }));
        return;
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Сетевая ошибка при запросе к GitHub: ${err.message}` }));
        return;
      }
    }

    // 1. GET /api/nodes
    if (req.method === 'GET' && pathname === '/api/nodes') {
      const allNodes = registry.getAllNodes();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(allNodes));
      return;
    }

    // 2. GET /api/templates
    if (req.method === 'GET' && pathname === '/api/templates') {
      const user = await getUserFromRequest(req);
      const userId = url.searchParams.get('userId') || user?.id || undefined;
      const allTemplates = await templates.getAllAsync(userId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(allTemplates));
      return;
    }

    // 3. POST /api/templates or /api/templates/publish (Save template to PostgreSQL with user tenancy)
    if (req.method === 'POST' && (pathname === '/api/templates' || pathname === '/api/templates/publish')) {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const templateId = body.id || `tpl_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const templateToSave = {
        id: templateId,
        title: body.title || 'Пользовательский сценарий',
        description: body.description || '',
        category: body.category || 'Custom',
        tags: Array.isArray(body.tags) ? body.tags : (body.tags ? body.tags.split(',').map((t: string) => t.trim()) : ['Custom']),
        author: user?.name || body.author || 'Пользователь',
        userId: user ? user.id : (body.userId || 'default_user'),
        isPublic: body.isPublic !== undefined ? Boolean(body.isPublic) : false,
        graph: body.graph
      };

      // Encrypt sensitive secrets in template settings before persisting
      if (templateToSave.graph && Array.isArray(templateToSave.graph.nodes)) {
        const secretKeys = ['botToken', 'telegramBotToken', 'credentials', 'password', 'webhookSecret', 'token', 'apiKey'];
        for (const node of templateToSave.graph.nodes) {
          if (node.settings) {
            for (const k of Object.keys(node.settings)) {
              if (secretKeys.includes(k) && typeof node.settings[k] === 'string' && node.settings[k].length > 0) {
                if (!node.settings[k].includes(':')) {
                  node.settings[k] = SecretVault.encrypt(node.settings[k]);
                }
              }
            }
          }
        }
      }

      templates.publish(templateToSave, false);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Шаблон успешно сохранён в PostgreSQL', template: templateToSave }));
      return;
    }

    // 3b. DELETE /api/templates/:id (Protected with IDOR & Built-in checks)
    if (req.method === 'DELETE' && pathname.startsWith('/api/templates/')) {
      const id = pathname.replace('/api/templates/', '');
      const user = await getUserFromRequest(req);
      if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Необходима авторизация для удаления шаблона' }));
        return;
      }

      const existingTpl = templates.getById(id);
      if (existingTpl && (existingTpl as any).isBuiltin) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Запрещено удалять системные встроенные шаблоны' }));
        return;
      }

      if (existingTpl && existingTpl.userId && existingTpl.userId !== user.id && user.id !== 'admin' && existingTpl.userId !== 'default_user') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Отказано в доступе: вы не являетесь владельцем этого шаблона' }));
        return;
      }

      const deleted = await db.deleteTemplate(id, user.id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: deleted, id }));
      return;
    }

    // 4. POST /api/ai/generate-workflow & /api/ai/generate
    if (req.method === 'POST' && (pathname === '/api/ai/generate-workflow' || pathname === '/api/ai/generate')) {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const prompt = body.prompt || '';
      const generatedGraph = AiWorkflowGenerator.generateFromPrompt(prompt);

      // Auto-inject user's vault tokens into generated graph
      if (user) {
        for (const node of generatedGraph.nodes) {
          node.settings = node.settings || {};
          if (node.type === 'ai.explainer' || node.type === 'ai.gigachat') {
            if (user.gigachatCredentials) {
              node.settings.provider = 'gigachat';
              node.settings.credentials = user.gigachatCredentials;
            }
            if (user.gigachatScope) node.settings.scope = user.gigachatScope;
          }
          if (node.type === 'notify.channel' || node.type === 'notify.telegram') {
            if (user.telegramBotToken) {
              node.settings.telegramBotToken = user.telegramBotToken;
              node.settings.botToken = user.telegramBotToken;
            }
            if (user.telegramChatId) {
              node.settings.telegramChatId = user.telegramChatId;
              node.settings.chatId = user.telegramChatId;
            }
          }
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(generatedGraph));
      return;
    }

    // POST /api/ai/test-gigachat (Verify GigaChat credentials)
    if (req.method === 'POST' && pathname === '/api/ai/test-gigachat') {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const creds = (body.credentials || user?.gigachatCredentials || process.env.GIGACHAT_CREDENTIALS || '').trim();
      const scope = (body.scope || user?.gigachatScope || process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS').trim();

      if (!creds) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Авторизационные данные GigaChat не указаны (отсутствуют в запросе, профиле и .env)' }));
        return;
      }

      try {
        const { GigaChatClient } = await import('./ai/security-categorizer.ts');
        const client = GigaChatClient.getInstance();
        client.reloadConfig(creds, scope);
        const token = await client.getToken();
        if (token) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: 'Сбер GigaChat API подключён успешно!' }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Не удалось получить токен Сбер GigaChat. Проверьте Base64 ключ в профиле.' }));
        }
      } catch (err: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
      return;
    }

    // 5. POST /api/workflow/run
    if (req.method === 'POST' && pathname === '/api/workflow/run') {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const graph: WorkflowGraph = body.graph;
      const initialData = body.initialData || {};

      if (!graph || !graph.nodes) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Параметр graph обязателен' }));
        return;
      }

      if (user) {
        initialData.userId = user.id;
        initialData.user = sanitizeUser(user);

        // Auto-inject user's encrypted-then-decrypted profile tokens into nodes if empty
        for (const node of graph.nodes) {
          node.settings = node.settings || {};
          if (node.type === 'source.git') {
            const repoUrl = (node.settings.repoUrl || '').trim();
            const hasToken = node.settings.token && node.settings.token.trim();
            if (!hasToken) {
              if (repoUrl.includes('github.com') && user.githubToken) {
                node.settings.token = user.githubToken;
                console.log(`[Workflow Run] Авто-подстановка токена GitHub пользователя ${user.name} для ${repoUrl}`);
              } else if (repoUrl.includes('gitverse.ru') && user.gitverseToken) {
                node.settings.token = user.gitverseToken;
                console.log(`[Workflow Run] Авто-подстановка токена GitVerse пользователя ${user.name} для ${repoUrl}`);
              }
            }
          } else if (node.type === 'ai.explainer' || node.type === 'ai.gigachat') {
            if (!node.settings.credentials) {
              node.settings.credentials = user.gigachatCredentials || process.env.GIGACHAT_CREDENTIALS;
            }
            if (!node.settings.scope) {
              node.settings.scope = user.gigachatScope || process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS';
            }
          } else if (node.type === 'notify.channel' || node.type === 'notify.dispatch' || node.type === 'notify.telegram') {
            if (!node.settings.telegramBotToken && !node.settings.botToken) {
              node.settings.telegramBotToken = user.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
              node.settings.botToken = user.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
            }
            if ((!node.settings.telegramChatId || node.settings.telegramChatId === '@security_audit') && user.telegramChatId) {
              node.settings.telegramChatId = user.telegramChatId;
            }
            if ((!node.settings.chatId || node.settings.chatId === '@security_audit') && user.telegramChatId) {
              node.settings.chatId = user.telegramChatId;
            }
            if (!node.settings.yandexUser && user.yandexMailUser) {
              node.settings.yandexUser = user.yandexMailUser;
            }
            if (!node.settings.yandexPassword && user.yandexMailPassword) {
              node.settings.yandexPassword = user.yandexMailPassword;
            }
            if (!node.settings.yandexTo && user.yandexMailTo) {
              node.settings.yandexTo = user.yandexMailTo;
            }
            if (!node.settings.webhookUrl && user.webhookUrl) {
              node.settings.webhookUrl = user.webhookUrl;
            }
            if (!node.settings.webhookSecret && user.webhookSecret) {
              node.settings.webhookSecret = user.webhookSecret;
            }
          }
        }
      }

      // Execute DAG and broadcast live events to all connected SSE clients
      const result = await engine.executeWorkflow(graph, initialData, (event: WorkflowExecutionEvent) => {
        broadcastEvent(event);
      });

      // Extract findings and severity breakdown by node types
      const findings: any[] = extractWorkflowFindings(graph, result);
      let reportOutput: any = {};
      for (const node of graph.nodes) {
        if (node.type === 'report.dual' || node.type === 'report.json') {
          if (result.nodeOutputs[node.id]) {
            reportOutput = result.nodeOutputs[node.id];
            break;
          }
        }
      }
      if (!reportOutput.reportFiles) {
        reportOutput = result.nodeOutputs['node-report'] || {};
      }
      const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
      const highCount = findings.filter(f => f.severity === 'HIGH').length;
      const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
      const lowCount = findings.filter(f => f.severity === 'LOW').length;

      let repoUrl = '';
      for (const out of Object.values(result.nodeOutputs)) {
        if (out && (out as any).repoUrl) {
          repoUrl = (out as any).repoUrl;
          break;
        }
      }

      const runRecord = {
        id: result.runId,
        workflowId: result.workflowId,
        workflowName: graph.name || 'Unnamed Workflow',
        userId: user ? user.id : 'anonymous',
        repoUrl,
        timestamp: result.startTime,
        durationMs: result.durationMs,
        success: result.success,
        findingsCount: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        result
      };

      // Save to in-memory run history
      runHistory.unshift(runRecord);
      if (runHistory.length > 50) runHistory.pop();

      // Persist to PostgreSQL
      await db.saveWorkflowRun({
        id: result.runId,
        workflowId: result.workflowId,
        workflowName: graph.name || 'Unnamed Workflow',
        success: result.success,
        durationMs: result.durationMs,
        startTime: result.startTime,
        endTime: result.endTime,
        findingsCount: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        result
      });

      if (findings.length > 0) {
        await db.saveFindings(result.runId, findings);
      }

      if (reportOutput.reportFiles) {
        await db.saveReport({
          runId: result.runId,
          totalVulnerabilities: findings.length,
          summary: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
          jsonContent: reportOutput.submissionJson ? (typeof reportOutput.submissionJson === 'string' ? JSON.parse(reportOutput.submissionJson) : reportOutput.submissionJson) : { findings },
          markdownContent: reportOutput.reportFiles?.mdContent || ''
        });
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ...result, repoUrl }));
      return;
    }

    // 6. POST /api/workflow/run-node or /api/node/execute (Single node test run / data inspector)
    if (req.method === 'POST' && (pathname === '/api/workflow/run-node' || pathname === '/api/node/execute')) {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const nodeInstance = body.node;
      const inputs = body.inputs || {};

      if (user && nodeInstance) {
        nodeInstance.settings = nodeInstance.settings || {};
        if (nodeInstance.type === 'source.git') {
          const repoUrl = (nodeInstance.settings.repoUrl || '').trim();
          if (!nodeInstance.settings.token) {
            if (repoUrl.includes('github.com') && user.githubToken) nodeInstance.settings.token = user.githubToken;
            else if (repoUrl.includes('gitverse.ru') && user.gitverseToken) nodeInstance.settings.token = user.gitverseToken;
          }
        } else if (nodeInstance.type === 'ai.explainer' || nodeInstance.type === 'ai.gigachat') {
          if (!nodeInstance.settings.credentials) nodeInstance.settings.credentials = user.gigachatCredentials || process.env.GIGACHAT_CREDENTIALS;
          if (!nodeInstance.settings.scope) nodeInstance.settings.scope = user.gigachatScope || process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS';
        } else if (nodeInstance.type === 'notify.channel' || nodeInstance.type === 'notify.dispatch' || nodeInstance.type === 'notify.telegram') {
          if (!nodeInstance.settings.telegramBotToken && !nodeInstance.settings.botToken) {
            nodeInstance.settings.telegramBotToken = user.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
            nodeInstance.settings.botToken = user.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
          }
          if ((!nodeInstance.settings.telegramChatId || nodeInstance.settings.telegramChatId === '@security_audit') && user.telegramChatId) {
            nodeInstance.settings.telegramChatId = user.telegramChatId;
          }
          if ((!nodeInstance.settings.chatId || nodeInstance.settings.chatId === '@security_audit') && user.telegramChatId) {
            nodeInstance.settings.chatId = user.telegramChatId;
          }
          if (!nodeInstance.settings.yandexUser && user.yandexMailUser) nodeInstance.settings.yandexUser = user.yandexMailUser;
          if (!nodeInstance.settings.yandexPassword && user.yandexMailPassword) nodeInstance.settings.yandexPassword = user.yandexMailPassword;
          if (!nodeInstance.settings.yandexTo && user.yandexMailTo) nodeInstance.settings.yandexTo = user.yandexMailTo;
          if (!nodeInstance.settings.webhookUrl && user.webhookUrl) nodeInstance.settings.webhookUrl = user.webhookUrl;
          if (!nodeInstance.settings.webhookSecret && user.webhookSecret) nodeInstance.settings.webhookSecret = user.webhookSecret;
        }
      }

      const singleResult = await engine.runSingleNode(nodeInstance, inputs);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(singleResult));
      return;
    }

    // 7. GET /api/ci/config & /api/cicd/config
    if (req.method === 'GET' && (pathname === '/api/ci/config' || pathname === '/api/cicd/config')) {
      const type = url.searchParams.get('type') || 'github';
      const serverUrl = getPublicBaseUrl(req);
      const config = type === 'gitlab'
        ? CiCdManager.generateGitLabCi(serverUrl)
        : CiCdManager.generateGitHubWorkflow(serverUrl);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type, config }));
      return;
    }

    // 8. POST /api/ci/run and /api/v1/ci/run (Headless CI runner)
if (req.method === 'POST' && (pathname === '/api/ci/run' || pathname === '/api/v1/ci/run')) {
  const body = await parseJsonBody(req);
  const rawRepo = (body.repo || body.repository || '').trim();
  const normalizedFullRepo = rawRepo
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/\.git$/i, '')
    .trim();

  const ciTokenHeader = req.headers['x-ci-token'] as string;
  const authHeader = req.headers.authorization || '';
  const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : '';
  const token = ciTokenHeader || bearerToken;
  const expectedGlobalToken = process.env.CI_API_TOKEN || 'SECRET_CI_KEY';

  let authorized = false;
  let repoOwner: UserProfile | null = null;
  let boundWorkflowId: string | undefined;

  // 1. Проверка уникального per-repo токена из Vault
  if (token && normalizedFullRepo) {
    const rawSaved = await db.getSecret(`ci_repo:${normalizedFullRepo.toLowerCase()}`);
    if (rawSaved) {
      try {
        const parsed = JSON.parse(SecretVault.decrypt(rawSaved));
        const a = Buffer.from(token);
        const b = Buffer.from(String(parsed.token || ''));
        if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
          authorized = true;
          boundWorkflowId = parsed.workflowId;
          if (parsed.userId) {
            repoOwner = await db.getUserById(parsed.userId);
          }
        }
      } catch {}
    }
  }

  // 2. Fallback: глобальный CI_API_TOKEN или пользовательская сессия
  if (!authorized && token && token === expectedGlobalToken) {
    authorized = true;
  }
  if (!authorized) {
    const reqUser = await getUserFromRequest(req);
    if (reqUser) {
      authorized = true;
      repoOwner = reqUser;
    }
  }

  if (!authorized) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Неверный или отсутствующий токен авторизации CI' }));
    return;
  }

  const commitSha = body.commitSha || 'unknown-sha';
  const failOnCritical = body.failOnCritical !== false;
  const requestedWfId = body.workflowId || boundWorkflowId;

  let targetTemplate: any = null;
  if (requestedWfId) {
    targetTemplate = templates.getById(requestedWfId) || (await templates.getAllAsync()).find(t => t.id === requestedWfId);
  }
  if (!targetTemplate) {
    targetTemplate = templates.getById('template-full-audit')!;
  }

  // Клонируем граф и подменяем source.local -> source.git под присланный репозиторий
  const graph: WorkflowGraph = JSON.parse(JSON.stringify(targetTemplate.graph));
  const repoUrl = rawRepo
    ? (rawRepo.startsWith('http') ? rawRepo : `https://github.com/${normalizedFullRepo}.git`)
    : '';
  const branch = (body.branch || 'main').trim();

  for (const node of graph.nodes) {
    node.settings = node.settings || {};
    if (repoUrl && (node.type === 'source.local' || node.type === 'source.git')) {
      node.type = 'source.git';
      node.settings.repoUrl = repoUrl;
      node.settings.branch = branch;
      if (!node.settings.token && repoOwner?.githubToken) {
        node.settings.token = repoOwner.githubToken; // сработает даже для приватных репо
      }
    } else if ((node.type === 'ai.explainer' || node.type === 'ai.gigachat') && repoOwner) {
      if (!node.settings.credentials && repoOwner.gigachatCredentials) {
        node.settings.credentials = repoOwner.gigachatCredentials;
      }
    } else if ((node.type === 'notify.channel' || node.type === 'notify.telegram') && repoOwner) {
      if (!node.settings.telegramBotToken && repoOwner.telegramBotToken) {
        node.settings.telegramBotToken = repoOwner.telegramBotToken;
      }
      if ((!node.settings.telegramChatId || node.settings.telegramChatId === '@security_audit') && repoOwner.telegramChatId) {
        node.settings.telegramChatId = repoOwner.telegramChatId;
      }
    }
  }

  const initialData: Record<string, any> = { repoUrl, branch, commitSha };
  const result = await engine.executeWorkflow(graph, initialData, (event) => {
    broadcastEvent(event);
  });

      const findings: any[] = extractWorkflowFindings(graph, result);
      const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
      const highCount = findings.filter(f => f.severity === 'HIGH').length;
      const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
      const lowCount = findings.filter(f => f.severity === 'LOW').length;
      const hasBlockers = criticalCount > 0 || highCount > 0;

      const exitCode = (failOnCritical && hasBlockers) ? 1 : 0;
      const serverUrl = getPublicBaseUrl(req);
      const ciResult = {
        status: exitCode === 0 ? 'passed' : 'failed',
        exitCode,
        summary: {
          critical: criticalCount,
          high: highCount,
          medium: mediumCount,
          low: lowCount,
          total: findings.length
        },
        reportUrl: `${serverUrl}/api/reports/latest`,
        jsonReport: {
          findings: findings.map(sanitizeFindingForExport)
        },
        totalFindings: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        findings,
        summaryMarkdown: CiCdManager.formatPrComment({
          status: exitCode === 0 ? 'passed' : 'failed',
          exitCode,
          totalFindings: findings.length,
          criticalCount,
          highCount,
          summaryMarkdown: '',
          findings
        }, commitSha)
      };

      // Persist to PostgreSQL
      await db.saveWorkflowRun({
        id: result.runId,
        workflowId: result.workflowId,
        workflowName: 'CI/CD Pipeline Run',
        success: exitCode === 0,
        durationMs: result.durationMs,
        startTime: result.startTime,
        endTime: result.endTime,
        findingsCount: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        result
      });

      if (findings.length > 0) {
        await db.saveFindings(result.runId, findings);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(ciResult));
      return;
    }


    async function upsertGithubActionsSecret(
  fullRepo: string,
  githubToken: string,
  secretName: string,
  secretValue: string
): Promise<void> {
  const keyRes = await fetch(`https://api.github.com/repos/${fullRepo}/actions/secrets/public-key`, {
    headers: {
      'Authorization': `Bearer ${githubToken}`,
      'User-Agent': 'uncflow-AppSec',
      'Accept': 'application/vnd.github+json'
    }
  });
  if (!keyRes.ok) {
    const errText = await keyRes.text();
    throw new Error(`Не удалось получить public-key репозитория (${keyRes.status}): ${errText}`);
  }
  const { key, key_id } = await keyRes.json() as { key: string; key_id: string };

  await _sodium.ready;
  const binKey = _sodium.from_base64(key, _sodium.base64_variants.ORIGINAL);
  const binSec = _sodium.from_string(secretValue);
  const encBytes = _sodium.crypto_box_seal(binSec, binKey);
  const encryptedValue = _sodium.to_base64(encBytes, _sodium.base64_variants.ORIGINAL);

  const putSecRes = await fetch(`https://api.github.com/repos/${fullRepo}/actions/secrets/${secretName}`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${githubToken}`,
      'User-Agent': 'uncflow-AppSec',
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ encrypted_value: encryptedValue, key_id })
  });
  if (!putSecRes.ok) {
    const errText = await putSecRes.text();
    throw new Error(`Не удалось сохранить секрет ${secretName} в GitHub (${putSecRes.status}): ${errText}`);
  }
}


    // 8b. POST /api/ci/install-github (1-Click GitHub Actions installation)
if (req.method === 'POST' && pathname === '/api/ci/install-github') {
      const user = await getUserFromRequest(req);
      if (!user || !user.githubToken) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Необходима авторизация через GitHub или привязанный GitHub Token в профиле' }));
        return;
      }

      const body = await parseJsonBody(req);
      const fullRepo = (body.repo || '').trim(); // e.g. "owner/repo"
      const branch = (body.branch || 'main').trim();
      if (!fullRepo || !fullRepo.includes('/')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Укажите репозиторий в формате owner/repo' }));
        return;
      }

      try {
        const serverUrl = getPublicBaseUrl(req);
        const repoKey = `ci_repo:${fullRepo.toLowerCase()}`;

        // 1. Генерируем уникальный CI-токен для этого репозитория и сохраняем в Vault (БД)
        const repoCiToken = `unc_ci_${crypto.randomBytes(24).toString('hex')}`;
        const vaultPayload = SecretVault.encrypt(JSON.stringify({
          token: repoCiToken,
          userId: user.id,
          repo: fullRepo,
          workflowId: body.workflowId || 'template-full-audit'
        }));
        await db.saveSecret(repoKey, vaultPayload, `CI/CD token for ${fullRepo}`);

        // 2. Получаем публичный ключ репозитория для шифрования GitHub Actions Secret
        const keyRes = await fetch(`https://api.github.com/repos/${fullRepo}/actions/secrets/public-key`, {
          headers: {
            'Authorization': `Bearer ${user.githubToken}`,
            'User-Agent': 'uncflow-AppSec',
            'Accept': 'application/vnd.github+json'
          }
        });
        if (!keyRes.ok) {
          const errText = await keyRes.text();
          throw new Error(`Не удалось получить public-key репозитория (${keyRes.status}): ${errText}`);
        }
        const { key, key_id } = await keyRes.json() as { key: string; key_id: string };

        // 3. Шифруем токен через libsodium и сохраняем секрет UNCFLOW_CI_TOKEN в GitHub Actions
        const sodiumMod: any = (_sodium as any).default || _sodium;
        await sodiumMod.ready;
        const sodium = sodiumMod.from_base64 ? sodiumMod : (sodiumMod.default || _sodium);

        const binKey = sodium.from_base64(key, sodium.base64_variants.ORIGINAL);
        const binSec = sodium.from_string(repoCiToken);
        const encBytes = sodium.crypto_box_seal(binSec, binKey);
        const encryptedSecretValue = sodium.to_base64(encBytes, sodium.base64_variants.ORIGINAL);

        const putSecRes = await fetch(`https://api.github.com/repos/${fullRepo}/actions/secrets/UNCFLOW_CI_TOKEN`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${user.githubToken}`,
            'User-Agent': 'uncflow-AppSec',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            encrypted_value: encryptedSecretValue,
            key_id
          })
        });
        if (!putSecRes.ok) {
          const errText = await putSecRes.text();
          throw new Error(`Не удалось сохранить секрет UNCFLOW_CI_TOKEN в GitHub (${putSecRes.status}): ${errText}`);
        }

        // 4. Генерируем YAML (без открытых ключей, со ссылкой на секрет)
        const workflowYaml = CiCdManager.generateGitHubWorkflow(serverUrl, '${{ secrets.UNCFLOW_CI_TOKEN }}');
        const encodedContent = Buffer.from(workflowYaml).toString('base64');
        const filePath = '.github/workflows/security-gate.yml';

        // 5. Проверяем, есть ли уже этот файл (нужен sha для обновления)
        let fileSha: string | undefined;
        try {
          const checkRes = await fetch(`https://api.github.com/repos/${fullRepo}/contents/${filePath}?ref=${branch}`, {
            headers: {
              'Authorization': `Bearer ${user.githubToken}`,
              'User-Agent': 'uncflow-AppSec',
              'Accept': 'application/vnd.github.v3+json'
            }
          });
          if (checkRes.ok) {
            const fileData: any = await checkRes.json();
            fileSha = fileData.sha;
          }
        } catch {}

        // 6. Создаём или обновляем .github/workflows/security-gate.yml в репозитории пользователя
        const putPayload: any = {
          message: 'ci: add uncflow automated security gatekeeper workflow',
          content: encodedContent,
          branch
        };
        if (fileSha) putPayload.sha = fileSha;

        const putRes = await fetch(`https://api.github.com/repos/${fullRepo}/contents/${filePath}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${user.githubToken}`,
            'User-Agent': 'uncflow-AppSec',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(putPayload)
        });

        if (!putRes.ok) {
          const errData: any = await putRes.json().catch(() => ({}));
          throw new Error(errData.message || `GitHub API error ${putRes.status}`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `CI/CD подключён: секрет UNCFLOW_CI_TOKEN и файл ${filePath} установлены в ${fullRepo}!`,
          workflowPath: filePath,
          actionsUrl: `https://github.com/${fullRepo}/actions`
        }));
        return;
      } catch (err: any) {
        console.error('❌ [install-github error]:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err?.message || 'Internal Server Error' }));
        return;
      }
    }

    // ==============================================================
    // WEBHOOK & CI/CD TRIGGERS
    // ==============================================================

    // GET /api/webhook/info (List of webhook endpoints and setup documentation)
    if (req.method === 'GET' && pathname === '/api/webhook/info') {
      const serverUrl = getPublicBaseUrl(req);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        endpoints: {
          generic: `${serverUrl}/api/webhook/trigger`,
          github: `${serverUrl}/api/webhook/github`,
          gitlab: `${serverUrl}/api/webhook/gitlab`,
          gitverse: `${serverUrl}/api/webhook/gitverse`
        },
        supportedEvents: ['push', 'pull_request', 'tag_push'],
        description: 'Приём входящих Webhook-уведомлений для автоматического запуска аудита безопасности uncflow'
      }));
      return;
    }

    // POST /api/webhook/test-send (Test dispatching a webhook to an external URL)
    if (req.method === 'POST' && pathname === '/api/webhook/test-send') {
      const body = await parseJsonBody(req);
      const targetUrl = (body.url || '').trim() || process.env.WEBHOOK_URL || '';
      if (!targetUrl) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'URL вебхука не указан в блоке и отсутствует в .env (WEBHOOK_URL)' }));
        return;
      }

      // SSRF Protection: block private and loopback destinations unless explicitly permitted
      if (isPrivateOrLoopbackUrl(targetUrl)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'SSRF Blocked: Запросы к приватным и петлевым IP адресам запрещены политикой платформы uncflow' }));
        return;
      }

      const samplePayload = body.payload || {
        event: 'test_webhook_ping',
        timestamp: new Date().toISOString(),
        source: 'uncflow Platform Test',
        message: 'Проверка доступности вебхука'
      };

      try {
        const fetchHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
        const secret = (body.secret || '').trim() || process.env.WEBHOOK_SECRET || '';
        if (secret) fetchHeaders['X-Security-Token'] = secret;
        const testResp = await fetch(targetUrl, {
          method: 'POST',
          headers: fetchHeaders,
          body: JSON.stringify(samplePayload),
          signal: AbortSignal.timeout(6000)
        });
        const text = await testResp.text().catch(() => '');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: testResp.ok,
          status: testResp.status,
          statusText: testResp.statusText,
          responseBodySnippet: text.substring(0, 300)
        }));
      } catch (err: any) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          error: err.message
        }));
      }
      return;
    }

    // POST /api/notify/test-telegram (Test Telegram bot connectivity)
    if (req.method === 'POST' && pathname === '/api/notify/test-telegram') {
      const user = await getUserFromRequest(req);
      const body = await parseJsonBody(req);
      const botToken = (body.botToken || user?.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN || '').trim();
      let chatId = (body.chatId || user?.telegramChatId || process.env.TELEGRAM_CHAT_ID || '').trim();
      if ((!chatId || chatId === '@security_audit') && user?.telegramChatId) {
        chatId = user.telegramChatId;
      }

      if (!botToken || !chatId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          error: 'Не указаны botToken или chatId (и отсутствуют в профиле/env)'
        }));
        return;
      }

      try {
        const text = `🛡️ *uncflow — Тестовое оповещение*\n\n✅ Интеграция с Telegram настроена успешно!\n📅 ${new Date().toLocaleString('ru-RU')}`;
        const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'Markdown' }),
          signal: AbortSignal.timeout(6000)
        });
        const resJson = await resp.json();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: resp.ok && resJson.ok,
          messageId: resJson.result?.message_id,
          error: resJson.description
        }));
      } catch (err: any) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
      return;
    }

    // POST /api/notify/test-yandex (Test Yandex Mail SMTP SSL:465 connectivity)
    if (req.method === 'POST' && pathname === '/api/notify/test-yandex') {
      const body = await parseJsonBody(req);
      const user = (body.user || process.env.YANDEX_MAIL_USER || '').trim();
      const password = (body.password || process.env.YANDEX_MAIL_PASSWORD || '').trim();
      const to = (body.to || process.env.YANDEX_MAIL_TO || user || '').trim();

      const mailRes = await sendYandexMail({
        user,
        password,
        to,
        subject: 'uncflow: Тестовое сообщение Яндекс Почты',
        html: `<div style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; border: 1px solid #1e293b;">
          <h2 style="color: #38bdf8; margin: 0 0 10px 0;">🛡️ uncflow</h2>
          <p>Интеграция с Яндекс Почтой (smtp.yandex.ru:465 SSL/TLS) работает успешно!</p>
          <p style="color: #94a3b8; font-size: 13px;">Дата проверки: ${new Date().toLocaleString('ru-RU')}</p>
        </div>`
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(mailRes));
      return;
    }

    // POST /api/webhook (Accept incoming webhooks from GitHub, GitLab, GitVerse or CI/CD)
    if (req.method === 'POST' && (pathname === '/api/webhook' || pathname.startsWith('/api/webhook/'))) {
      const body = await parseJsonBody(req);
      const headers = req.headers;

      // Extract Git Repository & Branch info from GitHub, GitLab, GitVerse or direct payload
      const repoUrl = body.repository?.clone_url || 
                      body.repository?.html_url || 
                      body.project?.git_http_url || 
                      body.project?.web_url || 
                      body.repoUrl || 
                      body.repo || '';

      const rawRef = body.ref || body.pull_request?.head?.ref || body.branch || 'main';
      const branch = String(rawRef).replace(/^refs\/heads\//, '').trim() || 'main';
      const commitSha = body.after || body.checkout_sha || body.pull_request?.head?.sha || body.head_commit?.id || body.commitSha || 'HEAD';
      const author = body.pusher?.name || body.sender?.login || body.user_name || body.author || body.head_commit?.author?.name || 'Webhook CI';

      console.log(`📡 [Incoming Webhook]: Received event on ${pathname} for repo: "${repoUrl || 'local'}" (branch: ${branch}, commit: ${commitSha})`);

      // Find workflow to execute
      const requestedWfId = url.searchParams.get('workflowId') || body.workflowId;
      const allTpls = await templates.getAllAsync();

      let targetTemplate = requestedWfId ? allTpls.find(t => t.id === requestedWfId) : null;
      if (!targetTemplate) {
        // Look for any template with a trigger.webhook node
        targetTemplate = allTpls.find(t => t.graph?.nodes?.some((n: any) => n.type === 'trigger.webhook'));
      }
      if (!targetTemplate) {
        targetTemplate = templates.getById('template-cicd-gatekeeper') || templates.getById('template-full-audit')!;
      }

      // Clone graph so we don't mutate template in place
      const graph: WorkflowGraph = JSON.parse(JSON.stringify(targetTemplate.graph));

      // Inject repoUrl and branch into source node if present
      for (const n of graph.nodes) {
        if (n.type === 'source.git' && repoUrl) {
          n.settings = n.settings || {};
          n.settings.repoUrl = repoUrl;
          n.settings.branch = branch;
        }
      }

      // Also inject user's tokens if auth token present
      const user = await getUserFromRequest(req);
      if (user) {
        for (const n of graph.nodes) {
          if (n.type === 'source.git') {
            n.settings = n.settings || {};
            if (!n.settings.token) {
              if (repoUrl.includes('gitverse.ru') && user.gitverseToken) {
                n.settings.token = user.gitverseToken;
              } else if (user.githubToken) {
                n.settings.token = user.githubToken;
              }
            }
          }
        }
      }

      // Execute workflow with webhook payload
      const initialData = {
        start: true,
        trigger: true,
        repoUrl,
        branch,
        commitSha,
        author,
        payload: body
      };

      const result = await engine.executeWorkflow(graph, initialData, (event) => {
        broadcastEvent(event);
      });

      const findings: any[] = extractWorkflowFindings(graph, result);
      const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
      const highCount = findings.filter(f => f.severity === 'HIGH').length;
      const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
      const lowCount = findings.filter(f => f.severity === 'LOW').length;
      const passed = (criticalCount + highCount) === 0;

      // Persist to PostgreSQL
      await db.saveWorkflowRun({
        id: result.runId,
        workflowId: targetTemplate.id,
        workflowName: `${targetTemplate.title || graph.name} (Webhook)`,
        success: result.success && passed,
        durationMs: result.durationMs,
        startTime: result.startTime,
        endTime: result.endTime,
        findingsCount: findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        result
      });

      if (findings.length > 0) {
        await db.saveFindings(result.runId, findings);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        status: passed ? 'passed' : 'failed',
        runId: result.runId,
        workflowName: targetTemplate.title || graph.name,
        repoUrl,
        branch,
        commitSha,
        totalFindings: findings.length,
        criticalCount,
        highCount,
        passed,
        durationMs: result.durationMs,
        message: passed 
          ? 'Аудит безопасности успешно пройден. Блокирующих уязвимостей не обнаружено.' 
          : `Обнаружены уязвимости (${criticalCount} CRIT, ${highCount} HIGH). Сборка заблокирована.`
      }));
      return;
    }

    // ==============================================================
    // CRON SCHEDULER API
    // ==============================================================

    // GET /api/cron/jobs or GET /api/scheduler/jobs
    if (req.method === 'GET' && (pathname === '/api/cron/jobs' || pathname === '/api/scheduler/jobs')) {
      const jobs = await scheduler.discoverScheduledWorkflows();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        active: true,
        currentTime: new Date().toISOString(),
        count: jobs.length,
        jobs
      }));
      return;
    }

    // POST /api/cron/run-now or POST /api/scheduler/run-now
    if (req.method === 'POST' && (pathname === '/api/cron/run-now' || pathname === '/api/scheduler/run-now')) {
      const body = await parseJsonBody(req);
      const workflowId = body.workflowId || 'template-sca-monitor';
      try {
        const result = await scheduler.runJobNow(workflowId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, result }));
      } catch (err: any) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
      return;
    }

    // POST /api/cron/describe
    if (req.method === 'POST' && pathname === '/api/cron/describe') {
      const body = await parseJsonBody(req);
      const cron = body.cron || '0 14 * * *';
      const description = CronParser.describe(cron);
      const nextRun = CronParser.getNextRunDate(cron);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        cron,
        description,
        nextRun: nextRun.toISOString(),
        nextRunFormatted: nextRun.toLocaleString('ru-RU')
      }));
      return;
    }

    // 9. GET /api/history or /api/reports/history
    if (req.method === 'GET' && (pathname === '/api/history' || pathname === '/api/reports/history')) {
      const runs = await db.getWorkflowRuns(50, 0);
      const list = runs.length > 0 ? runs : runHistory;
      const normalizedRuns = list.map(r => ({
        ...r,
        runId: r.id || (r as any).runId,
        timestamp: r.startTime || (r as any).timestamp || r.createdAt || new Date().toISOString(),
        totalFindings: r.findingsCount !== undefined ? r.findingsCount : ((r as any).totalFindings || 0)
      }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(normalizedRuns));
      return;
    }

    // 9b. GET /api/history/:id
    if (req.method === 'GET' && pathname.startsWith('/api/history/')) {
      const id = pathname.replace('/api/history/', '');
      const run = await db.getWorkflowRunById(id);
      if (!run) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Запуск с id ${id} не найден` }));
        return;
      }
      const findings = await db.getFindings({ runId: id });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ run, findings }));
      return;
    }

    // 10. GET /api/reports/latest or /api/reports/sarif
    if (req.method === 'GET' && (pathname === '/api/reports/latest' || pathname === '/api/reports/sarif')) {
      const format = url.searchParams.get('format') || (pathname === '/api/reports/sarif' ? 'sarif' : 'json');

      // First try PostgreSQL reports table
      const dbReport = await db.getLatestReport();
      let findings: any[] = [];

      if (dbReport) {
        findings = dbReport.jsonContent?.findings || [];
        if (format === 'sarif') {
          const sarif = exportToSarif(findings);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename="uncflow-findings.sarif"'
          });
          res.end(JSON.stringify(sarif, null, 2));
          return;
        }

        const payload = {
          totalVulnerabilities: dbReport.totalVulnerabilities,
          summary: dbReport.summary,
          findings,
          json: dbReport.jsonContent,
          markdown: dbReport.markdownContent
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
        return;
      }

      // Fallback to disk files
      const jsonPath = path.resolve(process.cwd(), 'reports', 'submission-report.json');
      const mdPath = path.resolve(process.cwd(), 'reports', 'audit-report.md');
      const sarifPath = path.resolve(process.cwd(), 'reports', 'findings.sarif');

      let jsonContent: any = null;
      let mdContent: string = '';

      if (fs.existsSync(jsonPath)) {
        try { jsonContent = JSON.parse(fs.readFileSync(jsonPath, 'utf-8')); } catch {}
      }
      if (fs.existsSync(mdPath)) {
        try { mdContent = fs.readFileSync(mdPath, 'utf-8'); } catch {}
      }

      // Fallback to latest run in memory
      const rawFindings = jsonContent?.findings
        || extractWorkflowFindings(undefined, runHistory[0]?.result)
        || [];

      findings = Array.isArray(rawFindings) ? rawFindings : [];

      if (format === 'sarif') {
        if (fs.existsSync(sarifPath)) {
          try {
            const sarifFromFile = JSON.parse(fs.readFileSync(sarifPath, 'utf-8'));
            res.writeHead(200, {
              'Content-Type': 'application/json',
              'Content-Disposition': 'attachment; filename="uncflow-findings.sarif"'
            });
            res.end(JSON.stringify(sarifFromFile, null, 2));
            return;
          } catch {}
        }
        const sarif = exportToSarif(findings);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Disposition': 'attachment; filename="uncflow-findings.sarif"'
        });
        res.end(JSON.stringify(sarif, null, 2));
        return;
      }

      const critical = findings.filter((f: any) => f.severity === 'CRITICAL').length;
      const high = findings.filter((f: any) => f.severity === 'HIGH').length;
      const medium = findings.filter((f: any) => f.severity === 'MEDIUM').length;
      const low = findings.filter((f: any) => f.severity === 'LOW').length;

      const payload = {
        totalVulnerabilities: findings.length,
        summary: { critical, high, medium, low },
        findings,
        json: jsonContent || { findings },
        markdown: mdContent || '# Отчёт безопасности\n\nАудит успешно завершён.'
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
      return;
    }

    // 11. GET /api/findings (Search and filter across findings)
    if (req.method === 'GET' && pathname === '/api/findings') {
      const runId = url.searchParams.get('runId') || undefined;
      const category = url.searchParams.get('category') || undefined;
      const severity = url.searchParams.get('severity') || undefined;
      const search = url.searchParams.get('search') || undefined;
      const limit = parseInt(url.searchParams.get('limit') || '100', 10);
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);

      const findings = await db.getFindings({ runId, category, severity, search, limit, offset });
      const stats = await db.getFindingsStats();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ total: stats.total, stats, findings }));
      return;
    }

    // 12. GET /api/findings/stats
    if (req.method === 'GET' && pathname === '/api/findings/stats') {
      const stats = await db.getFindingsStats();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
      return;
    }

    // 13. GET /api/db/health or /api/health (PostgreSQL status & statistics)
    if (req.method === 'GET' && (pathname === '/api/db/health' || pathname === '/api/health')) {
      const health = await db.getHealth();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString(), database: health }));
      return;
    }

    // 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `Not found: ${pathname}` }));
  } catch (err: any) {
    console.error('API Error:', err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err?.message || 'Internal Server Error' }));
  }
});

function broadcastEvent(event: WorkflowExecutionEvent) {
  // Ensure no raw secret values are broadcasted over SSE
  const safeData = maskSensitiveText(JSON.stringify(event));
  const data = `data: ${safeData}\n\n`;
  for (const client of sseClients) {
    client.write(data);
  }
}

function parseJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

async function getUserFromRequest(req: http.IncomingMessage): Promise<UserProfile | null> {
  const authHeader = req.headers.authorization || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers.cookie) {
    const match = req.headers.cookie.match(/auth_token=([^;]+)/);
    if (match) token = match[1];
  }
  if (!token) {
    const url = new URL(req.url || '/', getPublicBaseUrl(req));
    token = url.searchParams.get('token') || '';
  }
  if (!token) return null;
  return await db.getUserBySessionToken(token);
}

function sanitizeUser(user: UserProfile) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    avatarUrl: user.avatarUrl,
    githubId: user.githubId,
    githubUsername: user.githubUsername,
    hasGithubToken: Boolean(user.githubToken),
    githubTokenMasked: user.githubToken ? SecretVault.mask(user.githubToken) : null,
    gitverseUsername: user.gitverseUsername,
    hasGitverseToken: Boolean(user.gitverseToken),
    gitverseTokenMasked: user.gitverseToken ? SecretVault.mask(user.gitverseToken) : null,
    hasGigachatCredentials: Boolean(user.gigachatCredentials),
    gigachatCredentialsMasked: user.gigachatCredentials ? SecretVault.mask(user.gigachatCredentials) : null,
    gigachatScope: user.gigachatScope || 'GIGACHAT_API_PERS',
    hasTelegramBotToken: Boolean(user.telegramBotToken),
    telegramBotTokenMasked: user.telegramBotToken ? SecretVault.mask(user.telegramBotToken) : null,
    telegramChatId: user.telegramChatId || '',
    yandexMailUser: user.yandexMailUser || '',
    hasYandexMailPassword: Boolean(user.yandexMailPassword),
    yandexMailPasswordMasked: user.yandexMailPassword ? '••••••••' : null,
    yandexMailTo: user.yandexMailTo || '',
    webhookUrl: user.webhookUrl || '',
    hasWebhookSecret: Boolean(user.webhookSecret),
    webhookSecretMasked: user.webhookSecret ? SecretVault.mask(user.webhookSecret) : null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

server.listen(PORT, async () => {
  console.log(`===============================================================`);
  console.log(`🚀 AI SECURITY WORKFLOW BACKEND SERVER RUNNING ON PORT ${PORT}`);
  console.log(`   REST API:   http://localhost:${PORT}/api`);
  console.log(`   Live SSE:   http://localhost:${PORT}/api/events`);
  console.log(`   Database:   PostgreSQL (Connecting...)`);
  console.log(`===============================================================`);

  // Initialize PostgreSQL and sync templates
  try {
    const ok = await db.init();
    if (ok) {
      await templates.syncFromDb();
      console.log(`🐘 [PostgreSQL Ready]: Tables & initial templates initialized.`);
    }
  } catch (err: any) {
    console.warn(`⚠️ [PostgreSQL]: Initial connect deferred (${err?.message})`);
  }

  // Start background Cron Scheduler (checks active schedules every 30 seconds)
  scheduler.start(30000);
});
