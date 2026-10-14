// Browser test of the web console (Playwright + Chromium): sign-in, buckets, uploads, folders,
// preview, share links, downloads, settings and deletion, all signed with SigV4 in the page.
//
//   S3RS_CONSOLE_URL=http://localhost:9000 S3RS_ACCESS_KEY=... S3RS_SECRET_KEY=... node tests/console.js [screenshot-dir]
const { chromium } = require('playwright');
const BASE = process.env.S3RS_CONSOLE_URL || 'http://localhost:9000';
const AK = process.env.S3RS_ACCESS_KEY || 'testkey';
const SK = process.env.S3RS_SECRET_KEY || 'testsecret';
const BUCKET = 'console-' + Math.random().toString(36).slice(2, 10);
const out = process.argv[2];
const shot = (page, name) => (out ? page.screenshot({ path: `${out}/${name}.png` }) : null);
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, acceptDownloads: true });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  const page = await ctx.newPage();
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') problems.push(m.text()); });
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  const step = (s) => console.log('step:', s);

  step('redirect to console');
  await page.goto(BASE + '/');
  if (!page.url().endsWith('/_console/')) throw new Error('no redirect: ' + page.url());

  step('wrong password');
  await page.fill('#ak', AK); await page.fill('#sk', 'definitely-wrong');
  await page.click('#login-form button[type=submit]');
  await page.waitForFunction(() => document.querySelector('#login-error').textContent.length > 0);
  console.log('  login error:', await page.textContent('#login-error'));

  step('login');
  await page.fill('#sk', SK);
  await page.check('#remember');
  await page.click('#login-form button[type=submit]');
  await page.waitForSelector('#app:not(.hidden)');

  step('create bucket');
  await page.click('#new-bucket');
  await page.fill('#f-name', BUCKET);
  await page.check('#f-versioning');
  await page.click('#modal-ok');
  await page.waitForSelector(`#buckets li.active:has-text("${BUCKET}")`);

  step('upload files');
  await page.setInputFiles('#upload-input', [
    { name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from('Hello from the s3rs console!\n'.repeat(3)) },
    { name: 'data.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ a: 1, b: [1, 2, 3] }, null, 2)) },
    { name: 'big file (1).bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(3 * 1024 * 1024, 7) },
  ]);
  await page.waitForSelector('tr:has-text("big file (1).bin")', { timeout: 20000 });
  await page.waitForSelector('tr:has-text("hello.txt")');

  step('new folder + nested upload');
  await page.click('#new-folder');
  await page.fill('#f-folder', 'docs & notes');
  await page.click('#modal-ok');
  await page.click('a:has-text("docs & notes/")');
  await page.waitForSelector('#crumbs a:has-text("docs & notes")');
  await page.setInputFiles('#upload-input', [{ name: 'ünïcode ✓.md', mimeType: 'text/markdown', buffer: Buffer.from('# Title\n') }]);
  await page.waitForSelector('tr:has-text("ünïcode ✓.md")', { timeout: 10000 });
  await page.click(`#crumbs a:has-text("${BUCKET}")`);
  await page.waitForSelector('tr:has-text("hello.txt")');
  await shot(page, 'console-objects');

  step('details + preview');
  await page.click('a:has-text("hello.txt")');
  await page.waitForSelector('#details pre');
  const pre = await page.textContent('#details pre');
  if (!pre.includes('Hello from the s3rs console')) throw new Error('preview: ' + pre);
  await shot(page, 'console-details');

  step('share link');
  await page.click('#details button:has-text("Share link")');
  await page.selectOption('#f-exp', '3600');
  await page.click('#modal-ok');
  await page.waitForSelector('#modal .share-url');
  const url = await page.inputValue('#modal .share-url');
  await page.click('#modal-ok');
  const shared = await (await fetch(url)).text();
  if (!shared.startsWith('Hello from')) throw new Error('share link failed: ' + shared.slice(0, 200));
  console.log('  share link ok');

  step('download');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#details button:has-text("Download")')]);
  console.log('  downloaded as', dl.suggestedFilename());

  step('double refresh shows no duplicates');
  const before = await page.locator('#rows tr').count();
  await page.click('#refresh'); await page.click('#refresh'); await page.click('#refresh');
  await page.waitForTimeout(500);
  const after = await page.locator('#rows tr').count();
  if (before !== after) throw new Error(`rows changed from ${before} to ${after} after repeated refresh`);

  step('non-ASCII download name');
  await page.setInputFiles('#upload-input', [{ name: 'ünïcode ✓.txt', mimeType: 'text/plain', buffer: Buffer.from('u') }]);
  await page.waitForSelector('tr:has-text("ünïcode ✓.txt")', { timeout: 10000 });
  const [dl2] = await Promise.all([page.waitForEvent('download'), page.click('tr:has-text("ünïcode ✓.txt") button:has-text("Download")')]);
  if (dl2.suggestedFilename() !== 'ünïcode ✓.txt') throw new Error('download name: ' + dl2.suggestedFilename());

  step('stored HTML cannot read the console session');
  await page.setInputFiles('#upload-input', [{ name: 'evil.html', mimeType: 'text/html',
    buffer: Buffer.from('<script>let v; try { v = sessionStorage.getItem("s3rs-console"); } catch (e) { v = "blocked"; } document.title = "RESULT:" + v;</script>') }]);
  await page.waitForSelector('tr:has-text("evil.html")', { timeout: 10000 });
  await page.click('tr:has-text("evil.html") button:has-text("Share")');
  await page.click('#modal-ok');
  await page.waitForSelector('#modal .share-url');
  const evilUrl = await page.inputValue('#modal .share-url');
  await page.click('#modal-ok');
  const consoleUrl = page.url();
  await page.goto(evilUrl);
  await page.waitForFunction(() => document.title.startsWith('RESULT:'));
  const title = await page.title();
  if (title.includes(SK)) throw new Error('stored HTML read the secret: ' + title);
  console.log('  stored HTML saw:', title);
  await page.goto(consoleUrl);
  await page.waitForSelector('#app:not(.hidden)');
  await page.waitForSelector('tr:has-text("evil.html")');

  step('settings: public read + website');
  await page.click('#settings');
  await page.waitForSelector('#f-acl');
  await page.selectOption('#f-acl', 'public-read');
  await page.check('#f-web');
  await page.click('#modal-ok');
  await page.waitForSelector('.toast:has-text("Settings saved")');
  const anon = await fetch(`${BASE}/${BUCKET}/hello.txt`);
  console.log('  anonymous GET after public-read:', anon.status);
  if (anon.status !== 200) throw new Error('public read not applied');

  step('delete selected (folder + files)');
  if (await page.isVisible('#details')) await page.click('#details-close');
  await page.check('#select-all');
  await page.click('#delete-selected');
  await page.click('#modal-ok');
  await page.waitForSelector('#list-empty:not(.hidden)');

  step('delete bucket');
  await page.click('#settings');
  await page.waitForSelector('#f-acl');
  await page.click('#modal-body button.danger');
  await page.click('#modal-ok');
  await page.waitForSelector('#empty-state:not(.hidden)');
  const buckets = await page.textContent('#buckets');
  if (buckets.includes(BUCKET)) throw new Error('bucket still listed');

  step('dark mode + mobile screenshot');
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.setViewportSize({ width: 390, height: 760 });
  await shot(page, 'console-mobile-dark');

  const unexpected = problems.filter((p) => !/status of (403|404)/.test(p));
  console.log('browser console problems:', unexpected.length ? unexpected : 'none');
  if (unexpected.length) throw new Error('unexpected browser errors');
  await browser.close();
  console.log('CONSOLE TEST OK');
})().catch((e) => { console.error('CONSOLE TEST FAILED:', e); process.exit(1); });
