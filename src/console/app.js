// s3rs web console: a small S3 client that signs every request in the browser (SigV4).
"use strict";

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ------------------------------------------------------------------ helpers

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c != null && c !== false) e.append(c instanceof Node ? c : String(c));
  }
  return e;
}

function hex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(data) {
  return hex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}

// RFC 3986 encoding as SigV4 expects (optionally keeping "/").
function uriEncode(s, keepSlash = false) {
  let out = "";
  for (const b of enc.encode(s)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-_.~]/.test(c) || (keepSlash && c === "/")) out += c;
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function formatSize(n) {
  if (n == null || n === "") return "";
  n = Number(n);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + " " + units[i];
}

function formatDate(s) {
  if (!s) return "";
  const d = new Date(s);
  return isNaN(d) ? s : d.toLocaleString();
}

function toast(msg, isError = false) {
  const t = el("div", { class: "toast" + (isError ? " error" : "") }, msg);
  $("toasts").append(t);
  setTimeout(() => t.remove(), isError ? 7000 : 3500);
}

function xmlText(node, tag) {
  const n = node.getElementsByTagName(tag)[0];
  return n ? n.textContent : null;
}

function baseName(key) {
  const k = key.endsWith("/") ? key.slice(0, -1) : key;
  return k.slice(k.lastIndexOf("/") + 1) + (key.endsWith("/") ? "/" : "");
}

// ------------------------------------------------------------------ S3 client

class S3Error extends Error {
  constructor(status, code, message) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
  }
}

const S3 = {
  ak: "", sk: "", region: "us-east-1",
  // Session token of temporary (STS) credentials.
  token: "",
  keyCache: new Map(),

  async signingKey(date, service = "s3") {
    const id = `${date}/${this.region}/${service}`;
    if (!this.keyCache.has(id)) {
      let k = await hmac(enc.encode("AWS4" + this.sk), date);
      k = await hmac(k, this.region);
      k = await hmac(k, service);
      this.keyCache.set(id, await hmac(k, "aws4_request"));
    }
    return this.keyCache.get(id);
  },

  // Sign a request; returns { url, headers } ready for fetch / XHR.
  async sign(method, path, { query = {}, headers = {}, payloadHash = EMPTY_SHA256, service = "s3" } = {}) {
    const amzDate = new Date().toISOString().replace(/[-:]|\.\d{3}/g, "");
    const date = amzDate.slice(0, 8);
    const h = {};
    for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v).trim();
    h["x-amz-date"] = amzDate;
    h["x-amz-content-sha256"] = payloadHash;
    if (this.token) h["x-amz-security-token"] = this.token;
    const all = { host: location.host, ...h };
    const names = Object.keys(all).sort();
    const canonicalUri = uriEncode(path, true);
    const canonicalQuery = Object.keys(query)
      .map((k) => [uriEncode(k), uriEncode(String(query[k]))])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join("&");
    const creq = [method, canonicalUri, canonicalQuery, names.map((n) => `${n}:${all[n]}\n`).join(""), names.join(";"), payloadHash].join("\n");
    const scope = `${date}/${this.region}/${service}/aws4_request`;
    const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(creq)].join("\n");
    const sig = hex(await hmac(await this.signingKey(date, service), sts));
    h["authorization"] = `AWS4-HMAC-SHA256 Credential=${this.ak}/${scope}, SignedHeaders=${names.join(";")}, Signature=${sig}`;
    return { url: canonicalUri + (canonicalQuery ? "?" + canonicalQuery : ""), headers: h };
  },

  // Presigned GET URL (query-string authentication).
  async presign(path, expires, extraQuery = {}) {
    const amzDate = new Date().toISOString().replace(/[-:]|\.\d{3}/g, "");
    const date = amzDate.slice(0, 8);
    const scope = `${date}/${this.region}/s3/aws4_request`;
    const query = {
      ...extraQuery,
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": `${this.ak}/${scope}`,
      "X-Amz-Date": amzDate,
      "X-Amz-Expires": String(expires),
      "X-Amz-SignedHeaders": "host",
    };
    if (this.token) query["X-Amz-Security-Token"] = this.token;
    const canonicalUri = uriEncode(path, true);
    const canonicalQuery = Object.keys(query)
      .map((k) => [uriEncode(k), uriEncode(query[k])])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join("&");
    const creq = ["GET", canonicalUri, canonicalQuery, `host:${location.host}\n`, "host", "UNSIGNED-PAYLOAD"].join("\n");
    const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(creq)].join("\n");
    const sig = hex(await hmac(await this.signingKey(date), sts));
    return `${location.origin}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${sig}`;
  },

  async request(method, path, { query = {}, headers = {}, body = null, service = "s3" } = {}) {
    const bytes = typeof body === "string" ? enc.encode(body) : body;
    const payloadHash = bytes ? await sha256Hex(bytes) : EMPTY_SHA256;
    const s = await this.sign(method, path, { query, headers, payloadHash, service });
    const resp = await fetch(s.url, { method, headers: s.headers, body: bytes, cache: "no-store" });
    if (!resp.ok && resp.status !== 304) {
      let code = null, message = null;
      const text = method === "HEAD" ? "" : await resp.text();
      if (text.startsWith("<")) {
        const doc = new DOMParser().parseFromString(text, "application/xml");
        code = xmlText(doc, "Code");
        message = xmlText(doc, "Message");
      }
      // The console's session ran out: sign in again.
      if (code === "ExpiredToken" && this.token) logout();
      throw new S3Error(resp.status, code, message ? `${code}: ${message}` : code || `HTTP ${resp.status}`);
    }
    return resp;
  },

  async xml(method, path, opts) {
    const resp = await this.request(method, path, opts);
    return new DOMParser().parseFromString(await resp.text(), "application/xml");
  },

  // Temporary credentials for the current key (STS AssumeRole).
  async assumeRole(seconds) {
    const body = `Action=AssumeRole&Version=2011-06-15&RoleSessionName=console&DurationSeconds=${seconds}`;
    const doc = await this.xml("POST", "/", { body, service: "sts", headers: { "content-type": "application/x-www-form-urlencoded" } });
    return {
      ak: xmlText(doc, "AccessKeyId"), sk: xmlText(doc, "SecretAccessKey"), token: xmlText(doc, "SessionToken"),
      expires: Date.parse(xmlText(doc, "Expiration")),
    };
  },

  async listBuckets() {
    const doc = await this.xml("GET", "/");
    return [...doc.getElementsByTagName("Bucket")].map((b) => ({ name: xmlText(b, "Name"), created: xmlText(b, "CreationDate") }));
  },

  async list(bucket, prefix, token, delimiter = "/") {
    const query = { "list-type": "2", prefix, "max-keys": "500" };
    if (delimiter) query.delimiter = delimiter;
    if (token) query["continuation-token"] = token;
    const doc = await this.xml("GET", `/${bucket}`, { query });
    return {
      prefixes: [...doc.getElementsByTagName("CommonPrefixes")].map((p) => xmlText(p, "Prefix")),
      objects: [...doc.getElementsByTagName("Contents")].map((c) => ({
        key: xmlText(c, "Key"), size: xmlText(c, "Size"), modified: xmlText(c, "LastModified"),
      })),
      next: xmlText(doc, "IsTruncated") === "true" ? xmlText(doc, "NextContinuationToken") : null,
    };
  },

  // Delete keys (or versions) in batches of 1000.
  async deleteMany(bucket, items) {
    let failed = 0;
    for (let i = 0; i < items.length; i += 1000) {
      const batch = items.slice(i, i + 1000);
      const body = "<Delete><Quiet>true</Quiet>" + batch.map((it) => {
        const k = new XMLSerializer().serializeToString(document.createTextNode(it.key));
        return `<Object><Key>${k}</Key>${it.version ? `<VersionId>${it.version}</VersionId>` : ""}</Object>`;
      }).join("") + "</Delete>";
      const doc = await this.xml("POST", `/${bucket}`, { query: { delete: "" }, body, headers: { "content-type": "application/xml" } });
      failed += doc.getElementsByTagName("Error").length;
    }
    return failed;
  },

  async allKeys(bucket, prefix) {
    const keys = [];
    let token = null;
    do {
      const page = await this.list(bucket, prefix, token, "");
      keys.push(...page.objects.map((o) => ({ key: o.key })));
      token = page.next;
    } while (token);
    return keys;
  },

  // Every version (and delete marker) of one key, newest first.
  async versionsOf(bucket, key) {
    const out = [];
    let km = null, vm = null;
    for (;;) {
      const query = { versions: "", prefix: key, "max-keys": "1000" };
      if (km) { query["key-marker"] = km; if (vm) query["version-id-marker"] = vm; }
      const doc = await this.xml("GET", `/${bucket}`, { query });
      const entries = [...doc.documentElement.children].filter((n) => n.localName === "Version" || n.localName === "DeleteMarker");
      for (const v of entries) {
        if (xmlText(v, "Key") !== key) continue;
        out.push({
          version: xmlText(v, "VersionId"), latest: xmlText(v, "IsLatest") === "true", marker: v.localName === "DeleteMarker",
          modified: xmlText(v, "LastModified"), size: xmlText(v, "Size"),
        });
      }
      km = xmlText(doc, "NextKeyMarker");
      vm = xmlText(doc, "NextVersionIdMarker");
      // Stop once the listing has moved past this key.
      if (xmlText(doc, "IsTruncated") !== "true" || km !== key) return out;
    }
  },

  async allVersions(bucket) {
    const out = [];
    let km = null, vm = null;
    for (;;) {
      const query = { versions: "", "max-keys": "1000" };
      if (km) { query["key-marker"] = km; if (vm) query["version-id-marker"] = vm; }
      const doc = await this.xml("GET", `/${bucket}`, { query });
      for (const tag of ["Version", "DeleteMarker"]) {
        for (const v of doc.getElementsByTagName(tag)) out.push({ key: xmlText(v, "Key"), version: xmlText(v, "VersionId") });
      }
      if (xmlText(doc, "IsTruncated") !== "true") return out;
      km = xmlText(doc, "NextKeyMarker");
      vm = xmlText(doc, "NextVersionIdMarker");
    }
  },
};

// ------------------------------------------------------------------ state

const state = { buckets: [], bucket: null, prefix: "", token: null, selected: new Set(), items: [] };

function objectPath(key) {
  return `/${state.bucket}/${key}`;
}

// Browsers remove "." and ".." path segments from URLs, so such keys can't be read from here.
function browserReachable(key) {
  return !key.split("/").some((s) => s === "." || s === "..");
}

// ------------------------------------------------------------------ login

// Sign in with a key, or with saved session credentials (`token`, `user`).
async function login(ak, sk, region, remember, saved = null) {
  S3.ak = ak; S3.sk = sk; S3.region = region; S3.token = saved ? saved.token : ""; S3.keyCache.clear();
  state.buckets = await S3.listBuckets();
  const user = saved ? saved.user : ak;
  // Work with 12-hour session credentials from here on, so the key's own secret is not kept
  // (or saved) by the page. Servers without STS keep using the key.
  if (!saved) {
    try {
      const s = await S3.assumeRole(12 * 3600);
      S3.ak = s.ak; S3.sk = s.sk; S3.token = s.token; S3.keyCache.clear();
      // By default nothing is saved; reloading signs out.
      if (remember) {
        try {
          sessionStorage.setItem("s3rs-console", JSON.stringify({ ak: s.ak, sk: s.sk, token: s.token, user, region, expires: s.expires }));
        } catch (_) { /* private mode */ }
      }
    } catch (_) { /* keep the key */ }
  }
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("whoami").textContent = `${user} @ ${location.host}`;
  renderBuckets();
  let fromHash = "";
  try { fromHash = decodeURIComponent(location.hash.slice(1)); } catch (_) { /* malformed link */ }
  if (fromHash) {
    const [b, ...rest] = fromHash.split("/");
    if (state.buckets.some((x) => x.name === b)) openBucket(b, rest.join("/"));
  }
}

function logout() {
  try { sessionStorage.removeItem("s3rs-console"); } catch (_) { /* ignore */ }
  location.hash = "";
  location.reload();
}

// ------------------------------------------------------------------ buckets

function renderBuckets() {
  const f = $("bucket-filter").value.trim().toLowerCase();
  const list = $("buckets");
  list.replaceChildren(...state.buckets.filter((b) => b.name.includes(f)).map((b) =>
    el("li", { class: b.name === state.bucket ? "active" : "", title: b.name, onclick: () => openBucket(b.name, "") }, b.name)));
  if (!state.buckets.length) list.append(el("li", { class: "muted" }, "No buckets yet"));
}

async function refreshBuckets() {
  state.buckets = await S3.listBuckets();
  renderBuckets();
}

async function createBucket() {
  const name = await prompt("Create bucket", [
    el("label", {}, "Bucket name", el("input", { id: "f-name", required: true, pattern: "[a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]", placeholder: "my-bucket" })),
    el("p", { class: "muted" }, "3-63 characters: lowercase letters, digits, dots and hyphens."),
    el("label", { class: "radio" }, el("input", { type: "checkbox", id: "f-versioning" }), "Enable versioning"),
    el("label", { class: "radio" }, el("input", { type: "checkbox", id: "f-lock" }), "Enable Object Lock (implies versioning)"),
  ], "Create", () => ({ name: $("f-name").value.trim(), versioning: $("f-versioning").checked, lock: $("f-lock").checked }));
  if (!name) return;
  try {
    await S3.request("PUT", `/${name.name}`, { headers: name.lock ? { "x-amz-bucket-object-lock-enabled": "true" } : {} });
    if (name.versioning && !name.lock) await setVersioning(name.name, "Enabled");
    await refreshBuckets();
    openBucket(name.name, "");
    toast(`Bucket ${name.name} created`);
  } catch (e) { toast(e.message, true); }
}

async function setVersioning(bucket, status) {
  await S3.request("PUT", `/${bucket}`, {
    query: { versioning: "" },
    body: `<VersioningConfiguration><Status>${status}</Status></VersioningConfiguration>`,
    headers: { "content-type": "application/xml" },
  });
}

// ------------------------------------------------------------------ object browser

function openBucket(bucket, prefix) {
  state.bucket = bucket;
  state.prefix = prefix;
  $("search").value = "";
  closeDetails();
  renderBuckets();
  $("empty-state").classList.add("hidden");
  $("browser").classList.remove("hidden");
  history.replaceState(null, "", "#" + encodeURIComponent(`${bucket}/${prefix}`).replace(/%2F/g, "/"));
  loadList(false);
}

function renderCrumbs() {
  const parts = state.prefix.split("/").filter(Boolean);
  const crumbs = [el("a", { onclick: () => openBucket(state.bucket, "") }, state.bucket)];
  let acc = "";
  for (const p of parts) {
    acc += p + "/";
    const target = acc;
    crumbs.push(el("span", { class: "sep" }, "/"), el("a", { onclick: () => openBucket(state.bucket, target) }, p));
  }
  $("crumbs").replaceChildren(...crumbs);
}

let listSeq = 0;

async function loadList(append) {
  renderCrumbs();
  // Only the latest listing request may update the view (navigation can overtake a slow one).
  const seq = ++listSeq;
  const filter = $("search").value;
  if (!append) refreshUsage();
  try {
    const page = await S3.list(state.bucket, state.prefix + filter, append ? state.token : null);
    if (seq !== listSeq) return;
    if (!append) { state.items = []; state.selected.clear(); }
    state.token = page.next;
    state.items.push(...page.prefixes.map((p) => ({ key: p, folder: true })));
    state.items.push(...page.objects.filter((o) => o.key !== state.prefix).map((o) => ({ ...o, folder: false })));
    renderRows();
  } catch (e) {
    if (seq !== listSeq) return;
    toast(e.message, true);
    if (e.code === "NoSuchBucket") { await refreshBuckets(); $("browser").classList.add("hidden"); $("empty-state").classList.remove("hidden"); }
  }
}

async function refreshUsage() {
  const bucket = state.bucket;
  $("usage").textContent = "";
  try {
    const doc = await S3.xml("GET", `/${bucket}`, { query: { usage: "" } });
    if (bucket !== state.bucket) return;
    const n = Number(xmlText(doc, "Objects") || 0);
    const maxBytes = xmlText(doc, "MaxBytes");
    let text = `${n.toLocaleString()} object${n === 1 ? "" : "s"} · ${formatSize(xmlText(doc, "Bytes") || 0)}`;
    if (maxBytes) text += ` of ${formatSize(maxBytes)}`;
    const pending = Number(xmlText(doc, "MultipartBytes") || 0);
    if (pending > 0) text += ` (+ ${formatSize(pending)} in unfinished uploads)`;
    $("usage").textContent = text;
  } catch (_) { /* usage needs s3:GetBucketUsage; just leave it out */ }
}

function renderRows() {
  const rows = state.items.map((it) => {
    const name = baseName(it.key);
    const check = el("input", { type: "checkbox", "aria-label": "Select " + name, onchange: (ev) => {
      ev.target.checked ? state.selected.add(it.key) : state.selected.delete(it.key);
      renderSelection();
    } });
    check.checked = state.selected.has(it.key);
    if (it.folder) {
      return el("tr", {},
        el("td", { class: "check" }, check),
        el("td", { class: "name" }, el("span", { class: "icon" }, "▸"), el("a", { onclick: () => openBucket(state.bucket, it.key) }, name)),
        el("td", { class: "num" }, ""), el("td", { class: "hide-sm" }, ""),
        el("td", { class: "actions" }, el("button", { class: "ghost small danger", onclick: () => deleteKeys([it.key]) }, "Delete")));
    }
    if (!browserReachable(it.key)) {
      return el("tr", {},
        el("td", { class: "check" }, check),
        el("td", { class: "name", title: "Keys with \".\" or \"..\" path segments can't be opened from a browser; use an S3 client." },
          el("span", { class: "icon" }, "·"), name, el("span", { class: "muted" }, " (not reachable from a browser)")),
        el("td", { class: "num" }, formatSize(it.size)),
        el("td", { class: "hide-sm muted" }, formatDate(it.modified)),
        el("td", { class: "actions" }));
    }
    return el("tr", {},
      el("td", { class: "check" }, check),
      el("td", { class: "name" }, el("span", { class: "icon" }, "·"), el("a", { onclick: () => showDetails(it.key) }, name)),
      el("td", { class: "num" }, formatSize(it.size)),
      el("td", { class: "hide-sm muted" }, formatDate(it.modified)),
      el("td", { class: "actions" },
        el("button", { class: "ghost small", onclick: () => download(it.key) }, "Download"),
        el("button", { class: "ghost small", onclick: () => share(it.key) }, "Share")));
  });
  $("rows").replaceChildren(...rows);
  $("list-empty").classList.toggle("hidden", state.items.length > 0);
  $("load-more").classList.toggle("hidden", !state.token);
  renderSelection();
}

function renderSelection() {
  const n = state.selected.size;
  $("selection-bar").classList.toggle("hidden", n === 0);
  $("selection-count").textContent = `${n} selected`;
  $("select-all").checked = n > 0 && n === state.items.length;
}

async function deleteKeys(keys) {
  const folders = keys.filter((k) => k.endsWith("/"));
  const what = keys.length === 1 ? `“${baseName(keys[0])}”` : `${keys.length} items`;
  const ok = await confirmDialog("Delete", `Delete ${what}?` + (folders.length ? " Folders are deleted with everything in them." : "") +
    " In versioned buckets this adds delete markers; older versions are kept.", "Delete");
  if (!ok) return;
  try {
    const items = keys.filter((k) => !k.endsWith("/")).map((key) => ({ key }));
    for (const f of folders) items.push(...await S3.allKeys(state.bucket, f));
    const failed = await S3.deleteMany(state.bucket, items);
    toast(failed ? `${failed} of ${items.length} objects could not be deleted` : `Deleted ${items.length} object(s)`, failed > 0);
  } catch (e) { toast(e.message, true); }
  closeDetails();
  loadList(false);
}

async function newFolder() {
  const name = await prompt("New folder", [el("label", {}, "Folder name", el("input", { id: "f-folder", required: true }))],
    "Create", () => $("f-folder").value.trim().replace(/^\/+|\/+$/g, ""));
  if (!name) return;
  try {
    await S3.request("PUT", objectPath(state.prefix + name + "/"), { body: new Uint8Array(0) });
    loadList(false);
  } catch (e) { toast(e.message, true); }
}

async function download(key, version) {
  try {
    // ASCII fallback plus RFC 5987 filename* so non-ASCII names survive.
    const name = baseName(key);
    const ascii = name.replace(/[^\x20-\x7e]|["\\]/g, "_");
    const disposition = `attachment; filename="${ascii}"; filename*=UTF-8''${uriEncode(name)}`;
    const extra = { "response-content-disposition": disposition };
    if (version) extra.versionId = version;
    const url = await S3.presign(objectPath(key), 300, extra);
    el("a", { href: url, download: baseName(key) }).click();
  } catch (e) { toast(e.message, true); }
}

async function share(key) {
  const choice = await prompt("Share link", [
    el("p", { class: "muted" }, "Anyone with the link can download this object until it expires."),
    el("label", {}, "Expires after", el("select", { id: "f-exp" },
      el("option", { value: "3600" }, "1 hour"), el("option", { value: "86400", selected: true }, "1 day"),
      el("option", { value: "604800" }, "7 days (maximum)"))),
  ], "Create link", () => Number($("f-exp").value));
  if (!choice) return;
  let url;
  try { url = await S3.presign(objectPath(key), choice); } catch (e) { toast(e.message, true); return; }
  try { await navigator.clipboard.writeText(url); toast("Link copied to the clipboard"); } catch (_) { /* fall through */ }
  await prompt("Share link", [el("input", { class: "share-url", value: url, readonly: true, onfocus: (e) => e.target.select() })], "Done", () => true);
}

// ------------------------------------------------------------------ uploads

let uploadQueue = [];
let activeUploads = 0;

function enqueueUploads(files) {
  if (!state.bucket) return;
  $("uploads").classList.remove("hidden");
  for (const file of files) {
    const key = state.prefix + (file.webkitRelativePath || file.name);
    const bar = el("div");
    const status = el("span", {}, "waiting");
    const row = el("div", { class: "upload" }, el("div", { class: "label" }, el("span", { title: key }, key), status), el("div", { class: "bar" }, bar));
    $("uploads").append(row);
    uploadQueue.push({ file, key, bar, status, row, bucket: state.bucket });
  }
  pumpUploads();
}

function pumpUploads() {
  while (activeUploads < 3 && uploadQueue.length) {
    const job = uploadQueue.shift();
    activeUploads++;
    uploadOne(job).finally(() => {
      activeUploads--;
      pumpUploads();
      if (!activeUploads && !uploadQueue.length) {
        if (state.bucket === job.bucket) loadList(false);
        setTimeout(() => { if (!activeUploads && !uploadQueue.length) $("uploads").replaceChildren(); $("uploads").classList.toggle("hidden", !$("uploads").children.length); }, 4000);
      }
    });
  }
}

async function uploadOne(job) {
  const headers = { "content-type": job.file.type || "application/octet-stream" };
  const s = await S3.sign("PUT", `/${job.bucket}/${job.key}`, { headers, payloadHash: "UNSIGNED-PAYLOAD" });
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", s.url);
    for (const [k, v] of Object.entries(s.headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 100);
        job.bar.style.width = pct + "%";
        job.status.textContent = pct + "%";
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        job.row.classList.add("done"); job.bar.style.width = "100%"; job.status.textContent = "done";
      } else {
        const code = xhr.responseXML ? xmlText(xhr.responseXML, "Code") : null;
        job.row.classList.add("failed"); job.status.textContent = code || `HTTP ${xhr.status}`;
      }
      resolve();
    };
    xhr.onerror = () => { job.row.classList.add("failed"); job.status.textContent = "network error"; resolve(); };
    xhr.send(job.file);
  });
}

// ------------------------------------------------------------------ details panel

function closeDetails() {
  $("details").classList.add("hidden");
}

async function showDetails(key) {
  $("details-title").textContent = baseName(key);
  const body = $("details-body");
  body.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  $("details").classList.remove("hidden");
  try {
    const head = await S3.request("HEAD", objectPath(key));
    const h = head.headers;
    const rows = [
      ["Key", key], ["Size", `${formatSize(h.get("content-length"))} (${h.get("content-length")} bytes)`],
      ["Type", h.get("content-type")], ["Modified", formatDate(h.get("last-modified"))], ["ETag", h.get("etag")],
      ["Version", h.get("x-amz-version-id")], ["Encryption", h.get("x-amz-server-side-encryption") || (h.get("x-amz-server-side-encryption-customer-algorithm") ? "SSE-C" : null)],
      ["Lock mode", h.get("x-amz-object-lock-mode")], ["Retain until", h.get("x-amz-object-lock-retain-until-date") && formatDate(h.get("x-amz-object-lock-retain-until-date"))],
      ["Legal hold", h.get("x-amz-object-lock-legal-hold")], ["Cache-Control", h.get("cache-control")],
    ];
    for (const [k, v] of h.entries()) if (k.startsWith("x-amz-meta-")) rows.push([k.slice(11), v]);
    const kv = el("dl", { class: "kv" }, rows.filter(([, v]) => v).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
    const actions = el("div", { class: "row-actions" },
      el("button", { class: "primary small", onclick: () => download(key) }, "Download"),
      el("button", { class: "small", onclick: () => share(key) }, "Share link"),
      // Renaming moves only metadata; buckets with versioning can't (their history would split).
      h.get("x-amz-version-id") ? null : el("button", { class: "small", onclick: () => renameObject(key) }, "Rename"),
      el("button", { class: "small danger", onclick: () => deleteKeys([key]) }, "Delete"));
    const preview = await renderPreview(key, h);
    const access = await renderAccess(key);
    const versions = await renderVersions(key);
    body.replaceChildren(...[actions, preview, access, kv, versions].filter(Boolean));
  } catch (e) {
    body.replaceChildren(el("p", { class: "error" }, e.message));
  }
}

// Older versions of a key in a versioned bucket: download, restore (copy over the current
// version) or delete each.
async function renderVersions(key) {
  let versions;
  try {
    versions = await S3.versionsOf(state.bucket, key);
  } catch (e) {
    return null;
  }
  if (versions.length < 2 && versions.every((v) => v.version === "null")) return null;
  const rows = versions.map((v) => {
    const label = v.marker ? "Deleted" : formatSize(v.size);
    const actions = v.marker ? [] : [
      el("button", { class: "small", title: "Download this version", onclick: () => download(key, v.version) }, "Download"),
    ];
    if (!v.latest && !v.marker) {
      actions.push(el("button", { class: "small", title: "Make this the current version", onclick: () => restoreVersion(key, v.version) }, "Restore"));
    }
    actions.push(el("button", { class: "small danger", title: "Delete this version for good", onclick: () => deleteVersion(key, v) }, "Delete"));
    return el("tr", { class: v.latest ? "current" : "", title: `Version ${v.version}` },
      el("td", {}, formatDate(v.modified), v.latest ? el("span", { class: "badge" }, "current") : null),
      el("td", { class: "size" }, label),
      el("td", {}, el("div", { class: "row-actions tight" }, ...actions)));
  });
  return el("div", { class: "versions" }, el("h3", {}, `Versions (${versions.length})`), el("table", { class: "versions-table" }, ...rows));
}

// Who can read the object without signing in: anyone (its own public-read ACL, or a public
// bucket) or only signed-in keys.
async function renderAccess(key) {
  const publicIn = async (path, query) => {
    const doc = await S3.xml("GET", path, { query });
    return [...doc.getElementsByTagName("Grant")].some((g) => (xmlText(g, "URI") || "").endsWith("/AllUsers"));
  };
  let bucketPublic, objectPublic;
  try {
    bucketPublic = await publicIn(`/${state.bucket}`, { acl: "" });
    objectPublic = await publicIn(objectPath(key), { acl: "" });
  } catch (_) {
    return null; // ACLs turned off (BucketOwnerEnforced) or not allowed for this key
  }
  const url = location.origin + uriEncode(objectPath(key), true);
  const row = el("div", { class: "access" });
  if (bucketPublic) {
    row.append(el("span", { class: "badge" }, "Public"), " Everything in this bucket can be read by anyone.");
  } else if (objectPublic) {
    row.append(el("span", { class: "badge" }, "Public"), " ",
      el("input", { class: "share-url", value: url, readonly: true, onfocus: (e) => e.target.select() }), " ",
      el("button", { class: "small", onclick: () => setObjectAcl(key, "private") }, "Make private"));
  } else {
    row.append(el("span", { class: "badge muted" }, "Private"), " ",
      el("button", { class: "small", title: "Anyone with the link can read it, without signing in", onclick: () => setObjectAcl(key, "public-read") }, "Make public"));
  }
  return row;
}

async function setObjectAcl(key, acl) {
  try {
    await S3.request("PUT", objectPath(key), { query: { acl: "" }, headers: { "x-amz-acl": acl } });
    toast(acl === "private" ? "Only signed-in keys can read it now" : "Anyone with the link can read it now");
    showDetails(key);
  } catch (e) { toast(e.message, true); }
}

async function renameObject(key) {
  const target = await prompt("Rename", [
    el("label", {}, "New name", el("input", { id: "f-newkey", value: key, required: true, autocomplete: "off" })),
    el("p", { class: "muted" }, "Include folders in the name to move it (for example archive/2024/report.pdf)."),
  ], "Rename", () => $("f-newkey").value.trim());
  if (!target || target === key) return;
  try {
    await S3.request("PUT", objectPath(target), {
      query: { renameObject: "" },
      headers: { "x-amz-rename-source": `${state.bucket}/${uriEncode(key, true)}`, "if-none-match": "*" },
    });
    toast(`Renamed to ${target}`);
    loadList(false);
    showDetails(target);
  } catch (e) {
    toast(e.code === "PreconditionFailed" ? `“${target}” already exists.` : e.message, true);
  }
}

async function restoreVersion(key, version) {
  try {
    const source = `${state.bucket}/${uriEncode(key, true)}?versionId=${encodeURIComponent(version)}`;
    await S3.request("PUT", objectPath(key), { headers: { "x-amz-copy-source": source } });
    toast("Restored as the current version");
    showDetails(key);
    loadList(false);
  } catch (e) { toast(e.message, true); }
}

async function deleteVersion(key, v) {
  const what = v.marker ? "this delete marker" : "this version";
  const ok = await confirmDialog("Delete version", `Delete ${what} of “${baseName(key)}” for good? This cannot be undone.`, "Delete");
  if (!ok) return;
  try {
    await S3.request("DELETE", objectPath(key), { query: { versionId: v.version } });
    toast("Version deleted");
    showDetails(key);
    loadList(false);
  } catch (e) { toast(e.message, true); }
}

async function renderPreview(key, h) {
  const type = h.get("content-type") || "";
  const size = Number(h.get("content-length"));
  if (type.startsWith("image/") && size < 20 * 1024 * 1024) {
    return el("div", { class: "preview" }, el("img", { alt: "", src: await S3.presign(objectPath(key), 300) }));
  }
  const texty = type.startsWith("text/") || /json|xml|javascript|yaml|csv/.test(type) || /\.(txt|md|json|csv|log|ya?ml|toml|ini|html?|css|js|ts|rs|py|go|sh)$/i.test(key);
  if (texty && size > 0) {
    const resp = await S3.request("GET", objectPath(key), { headers: { range: "bytes=0-16383" } });
    let text = new TextDecoder().decode(await resp.arrayBuffer());
    if (size > 16384) text += "\n…";
    return el("div", { class: "preview" }, el("pre", { class: "mono" }, text));
  }
  return null;
}

// ------------------------------------------------------------------ bucket settings

async function bucketSettings() {
  const b = state.bucket;
  let versioning = "Off", publicRead = false, lock = false, website = null, quota = { bytes: "", objects: "" };
  let life = { expire: "", abort: "", noncurrent: "", others: [] };
  try {
    const v = await S3.xml("GET", `/${b}`, { query: { versioning: "" } });
    versioning = xmlText(v, "Status") || "Off";
    const acl = await S3.xml("GET", `/${b}`, { query: { acl: "" } });
    publicRead = [...acl.getElementsByTagName("Grant")].some((g) => (xmlText(g, "URI") || "").endsWith("/AllUsers") && xmlText(g, "Permission") === "READ");
    try { await S3.request("GET", `/${b}`, { query: { "object-lock": "" } }); lock = true; } catch (_) { /* not enabled */ }
    try { const w = await S3.xml("GET", `/${b}`, { query: { website: "" } }); website = { index: xmlText(w, "Suffix"), error: xmlText(w, "Key") }; } catch (_) { /* none */ }
    try { life = parseLifecycle(await S3.xml("GET", `/${b}`, { query: { lifecycle: "" } })); } catch (_) { /* none */ }
    try {
      const q = await S3.xml("GET", `/${b}`, { query: { quota: "" } });
      const mb = xmlText(q, "MaxBytes");
      quota = { bytes: mb ? String(Number(mb) / 2 ** 30) : "", objects: xmlText(q, "MaxObjects") || "" };
    } catch (_) { /* no permission */ }
  } catch (e) { toast(e.message, true); return; }

  let wantsDelete = false, wantsPolicy = false;
  const choice = await prompt(`Settings: ${b}`, [
    el("label", {}, "Versioning", el("select", { id: "f-ver", disabled: lock },
      el("option", { value: "Off", selected: versioning === "Off", disabled: versioning !== "Off" }, "Off"),
      el("option", { value: "Enabled", selected: versioning === "Enabled" }, "Enabled"),
      el("option", { value: "Suspended", selected: versioning === "Suspended", disabled: versioning === "Off" }, "Suspended"))),
    lock ? el("p", { class: "muted" }, "Object Lock is enabled, so versioning stays on.") : null,
    el("label", {}, "Access", el("select", { id: "f-acl" },
      el("option", { value: "private", selected: !publicRead }, "Private"),
      el("option", { value: "public-read", selected: publicRead }, "Public read (anyone can download and list)"))),
    el("label", { class: "radio" }, el("input", { type: "checkbox", id: "f-web", checked: !!website }), "Static website hosting"),
    el("label", {}, "Index document", el("input", { id: "f-index", value: website?.index || "index.html" })),
    el("label", {}, "Error document (optional)", el("input", { id: "f-error", value: website?.error || "" })),
    el("p", { class: "muted" }, "Websites are served on the server's website endpoint (--website-listen) and need public read access."),
    el("label", {}, "Quota: maximum size in GiB (empty = unlimited)", el("input", { id: "f-qbytes", type: "number", min: "0", step: "any", value: quota.bytes })),
    el("label", {}, "Quota: maximum number of objects (empty = unlimited)", el("input", { id: "f-qobjects", type: "number", min: "0", step: "1", value: quota.objects })),
    el("label", {}, "Delete objects after (days; empty = never)", el("input", { id: "f-expire", type: "number", min: "1", step: "1", value: life.expire })),
    el("label", {}, "Delete old versions after they're replaced (days)", el("input", { id: "f-noncurrent", type: "number", min: "1", step: "1", value: life.noncurrent })),
    el("label", {}, "Clean up unfinished uploads after (days)", el("input", { id: "f-abort", type: "number", min: "1", step: "1", value: life.abort })),
    life.others.length ? el("p", { class: "muted" }, `This bucket also has ${life.others.length} lifecycle rule(s) set by other tools; they are kept.`) : null,
    el("hr"),
    el("button", { type: "button", onclick: () => { wantsPolicy = true; $("modal").close("cancel"); } }, "Edit bucket policy…"), " ",
    el("button", { type: "button", class: "danger", onclick: () => { wantsDelete = true; $("modal").close("cancel"); } }, "Delete bucket…"),
  ], "Save", () => ({
    ver: $("f-ver").value, acl: $("f-acl").value, web: $("f-web").checked, index: $("f-index").value.trim(), error: $("f-error").value.trim(),
    qbytes: $("f-qbytes").value.trim(), qobjects: $("f-qobjects").value.trim(),
    expire: $("f-expire").value.trim(), noncurrent: $("f-noncurrent").value.trim(), abort: $("f-abort").value.trim(),
  }));
  if (wantsDelete) return deleteBucket(b);
  if (wantsPolicy) return editPolicy(b);
  if (!choice) return;
  try {
    if (choice.ver !== versioning && choice.ver !== "Off") await setVersioning(b, choice.ver);
    if ((choice.acl === "public-read") !== publicRead) await S3.request("PUT", `/${b}`, { query: { acl: "" }, headers: { "x-amz-acl": choice.acl } });
    if (choice.web) {
      const esc = (s) => new XMLSerializer().serializeToString(document.createTextNode(s));
      const doc = `<WebsiteConfiguration><IndexDocument><Suffix>${esc(choice.index || "index.html")}</Suffix></IndexDocument>` +
        (choice.error ? `<ErrorDocument><Key>${esc(choice.error)}</Key></ErrorDocument>` : "") + "</WebsiteConfiguration>";
      await S3.request("PUT", `/${b}`, { query: { website: "" }, body: doc, headers: { "content-type": "application/xml" } });
    } else if (website) {
      await S3.request("DELETE", `/${b}`, { query: { website: "" } });
    }
    if (choice.qbytes !== quota.bytes || choice.qobjects !== quota.objects) {
      const bytes = choice.qbytes ? Math.round(Number(choice.qbytes) * 2 ** 30) : 0;
      const objects = choice.qobjects ? Math.round(Number(choice.qobjects)) : 0;
      if (bytes || objects) {
        await S3.request("PUT", `/${b}`, {
          query: { quota: "" },
          body: `<BucketQuota><MaxBytes>${bytes}</MaxBytes><MaxObjects>${objects}</MaxObjects></BucketQuota>`,
          headers: { "content-type": "application/xml" },
        });
      } else {
        await S3.request("DELETE", `/${b}`, { query: { quota: "" } });
      }
    }
    if (choice.expire !== life.expire || choice.noncurrent !== life.noncurrent || choice.abort !== life.abort) {
      const doc = lifecycleDoc(choice, life.others);
      if (doc) {
        await S3.request("PUT", `/${b}`, { query: { lifecycle: "" }, body: doc, headers: { "content-type": "application/xml" } });
      } else {
        await S3.request("DELETE", `/${b}`, { query: { lifecycle: "" } });
      }
    }
    toast("Settings saved");
    refreshUsage();
  } catch (e) { toast(e.message, true); }
}

// The console manages three whole-bucket lifecycle rules (by id); other rules are kept as they are.
const LIFE_IDS = { expire: "console-expire", noncurrent: "console-noncurrent", abort: "console-abort" };

function parseLifecycle(doc) {
  const out = { expire: "", abort: "", noncurrent: "", others: [] };
  for (const rule of doc.getElementsByTagName("Rule")) {
    const id = xmlText(rule, "ID");
    const enabled = xmlText(rule, "Status") === "Enabled";
    if (id === LIFE_IDS.expire && enabled) out.expire = xmlText(rule, "Days") || "";
    else if (id === LIFE_IDS.noncurrent && enabled) out.noncurrent = xmlText(rule, "NoncurrentDays") || "";
    else if (id === LIFE_IDS.abort && enabled) out.abort = xmlText(rule, "DaysAfterInitiation") || "";
    else out.others.push(new XMLSerializer().serializeToString(rule).replace(/ xmlns="[^"]*"/g, ""));
  }
  return out;
}

function lifecycleDoc(choice, others) {
  const days = (v) => Math.max(1, Math.round(Number(v)));
  const rule = (id, action) => `<Rule><ID>${id}</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>${action}</Rule>`;
  const rules = [...others];
  if (choice.expire) rules.push(rule(LIFE_IDS.expire, `<Expiration><Days>${days(choice.expire)}</Days></Expiration>`));
  if (choice.noncurrent) rules.push(rule(LIFE_IDS.noncurrent, `<NoncurrentVersionExpiration><NoncurrentDays>${days(choice.noncurrent)}</NoncurrentDays></NoncurrentVersionExpiration>`));
  if (choice.abort) rules.push(rule(LIFE_IDS.abort, `<AbortIncompleteMultipartUpload><DaysAfterInitiation>${days(choice.abort)}</DaysAfterInitiation></AbortIncompleteMultipartUpload>`));
  return rules.length ? `<LifecycleConfiguration>${rules.join("")}</LifecycleConfiguration>` : null;
}

// The bucket policy as JSON text: an empty policy removes it.
async function editPolicy(b) {
  let current = "";
  try {
    const r = await S3.request("GET", `/${b}`, { query: { policy: "" } });
    current = JSON.stringify(JSON.parse(await r.text()), null, 2);
  } catch (e) {
    if (e.code !== "NoSuchBucketPolicy") { toast(e.message, true); return; }
  }
  const example = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: `arn:aws:s3:::${b}/public/*` }] }, null, 2);
  const text = await prompt(`Bucket policy: ${b}`, [
    el("textarea", {
      id: "f-policy", class: "policy", rows: "16", spellcheck: "false", placeholder: example,
      // Invalid JSON keeps the dialog open (with the browser's validation message).
      oninput: (e) => {
        const t = e.target.value.trim();
        try { if (t) JSON.parse(t); e.target.setCustomValidity(""); } catch (err) { e.target.setCustomValidity(`Not valid JSON: ${err.message}`); }
      },
    }, current),
    el("p", { class: "muted" }, "IAM policy JSON. Leave empty to remove the policy."),
  ], "Save", () => ({ t: $("f-policy").value.trim() }));
  if (!text) return;
  try {
    if (text.t) {
      await S3.request("PUT", `/${b}`, { query: { policy: "" }, body: text.t, headers: { "content-type": "application/json" } });
      toast("Bucket policy saved");
    } else if (current) {
      await S3.request("DELETE", `/${b}`, { query: { policy: "" } });
      toast("Bucket policy removed");
    }
  } catch (e) { toast(e.message, true); }
}

async function deleteBucket(b) {
  const ok = await confirmDialog("Delete bucket", `Delete bucket “${b}” and everything in it, including old versions? This cannot be undone.`, "Delete bucket");
  if (!ok) return;
  try {
    const items = await S3.allVersions(b);
    const failed = items.length ? await S3.deleteMany(b, items) : 0;
    if (failed) throw new Error(`${failed} object version(s) could not be deleted (Object Lock?)`);
    await S3.request("DELETE", `/${b}`);
    toast(`Bucket ${b} deleted`);
    state.bucket = null;
    history.replaceState(null, "", "#");
    $("browser").classList.add("hidden");
    $("empty-state").classList.remove("hidden");
    await refreshBuckets();
  } catch (e) { toast(e.message, true); }
}

// ------------------------------------------------------------------ access keys (admin API)

// The admin token stays in this page's memory only.
let adminToken = "";

async function admin(method, path = "", body = null) {
  const resp = await fetch(`/_admin/keys${path}`, {
    method, cache: "no-store", headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : null,
  });
  const text = await resp.text();
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    if (text.startsWith("<")) msg = xmlText(new DOMParser().parseFromString(text, "application/xml"), "Message") || msg;
    throw new S3Error(resp.status, null, msg);
  }
  return text ? JSON.parse(text) : null;
}

async function manageKeys() {
  if (!adminToken) {
    const t = await prompt("Admin token", [
      el("p", { class: "muted" }, "Managing access keys needs the server's admin token (--admin-token). It is kept only while this page is open."),
      el("label", {}, "Admin token", el("input", { id: "f-admin", type: "password", required: true, autocomplete: "off" })),
    ], "Continue", () => $("f-admin").value.trim());
    if (!t) return;
    adminToken = t;
  }
  let keys;
  try {
    keys = (await admin("GET")).keys;
  } catch (e) {
    if (e.status === 403) adminToken = "";
    toast(e.status === 403 ? "The admin token was refused (or the admin API is off)." : e.message, true);
    return;
  }
  let action = null;
  const rows = keys.map((k) => el("tr", {},
    el("td", { class: "mono" }, k.access_key),
    el("td", {}, k.description || (k.source === "file" ? "(credentials file)" : "")),
    el("td", {}, [k.read_only ? "read-only" : "read-write", k.buckets ? `buckets: ${k.buckets.join(", ")}` : null, k.policy ? "policy" : null,
      k.expires ? `expires ${formatDate(k.expires)}` : null].filter(Boolean).join(" · ")),
    el("td", {}, k.source === "api"
      ? el("button", { type: "button", class: "small danger", onclick: () => { action = { revoke: k.access_key }; $("modal").close("cancel"); } }, "Revoke")
      : null)));
  await prompt("Access keys", [
    el("table", { class: "keys-table" }, ...rows),
    el("button", { type: "button", class: "primary", onclick: () => { action = { create: true }; $("modal").close("cancel"); } }, "New key…"),
  ], "Done", () => true);
  if (action?.revoke) return revokeKey(action.revoke);
  if (action?.create) return createKey();
}

async function revokeKey(ak) {
  const ok = await confirmDialog("Revoke key", `Revoke ${ak}? Clients using it stop working at once.`, "Revoke");
  if (!ok) return;
  try { await admin("DELETE", `/${encodeURIComponent(ak)}`); toast(`Revoked ${ak}`); } catch (e) { toast(e.message, true); }
  manageKeys();
}

async function createKey() {
  const spec = await prompt("New access key", [
    el("label", {}, "Description", el("input", { id: "f-kdesc", autocomplete: "off" })),
    el("label", { class: "radio" }, el("input", { type: "checkbox", id: "f-kro" }), "Read-only"),
    el("label", {}, "Limit to buckets (comma-separated, * wildcards; empty = all)", el("input", { id: "f-kbuckets", autocomplete: "off" })),
    el("label", {}, "Expires after (hours; empty = never)", el("input", { id: "f-kexp", type: "number", min: "1", step: "1" })),
  ], "Create", () => {
    const body = { description: $("f-kdesc").value.trim(), read_only: $("f-kro").checked };
    const buckets = $("f-kbuckets").value.split(",").map((b) => b.trim()).filter(Boolean);
    if (buckets.length) body.buckets = buckets;
    if ($("f-kexp").value) body.expires_in = Math.round(Number($("f-kexp").value) * 3600);
    return body;
  });
  if (!spec) return manageKeys();
  let k;
  try { k = await admin("POST", "", spec); } catch (e) { toast(e.message, true); return; }
  const copy = (v) => el("input", { class: "share-url", value: v, readonly: true, onfocus: (e) => e.target.select() });
  await prompt("Key created", [
    el("p", {}, "Copy the secret key now: it is not shown again."),
    el("label", {}, "Access key", copy(k.access_key)),
    el("label", {}, "Secret key", copy(k.secret_key)),
  ], "Done", () => true);
  manageKeys();
}

// ------------------------------------------------------------------ dialogs

function prompt(title, fields, okLabel, collect) {
  return new Promise((resolve) => {
    const modal = $("modal");
    $("modal-title").textContent = title;
    $("modal-body").replaceChildren(...fields.filter(Boolean));
    $("modal-ok").textContent = okLabel;
    $("modal-ok").className = /delete/i.test(okLabel) ? "danger" : "primary";
    let result = null;
    const form = $("modal-form");
    const onSubmit = (ev) => {
      if (ev.submitter && ev.submitter.value === "ok") {
        if (!form.reportValidity()) { ev.preventDefault(); return; }
        result = collect();
      }
    };
    form.addEventListener("submit", onSubmit);
    modal.addEventListener("close", () => { form.removeEventListener("submit", onSubmit); resolve(result); }, { once: true });
    modal.showModal();
    const first = $("modal-body").querySelector("input:not([type=checkbox]), select");
    if (first) first.focus();
  });
}

function confirmDialog(title, text, okLabel) {
  return prompt(title, [el("p", {}, text)], okLabel, () => true);
}

// ------------------------------------------------------------------ wiring

document.addEventListener("DOMContentLoaded", () => {
  const region = document.querySelector('meta[name="s3rs-region"]').content || "us-east-1";
  $("region").value = region;
  if (!window.crypto || !crypto.subtle) {
    $("login-error").textContent = "This page needs a secure context (HTTPS or localhost) for request signing.";
  }
  $("login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("login-error").textContent = "";
    try {
      await login($("ak").value.trim(), $("sk").value, $("region").value.trim(), $("remember").checked);
    } catch (e) {
      $("login-error").textContent = e.code === "InvalidAccessKeyId" || e.code === "SignatureDoesNotMatch" ? "Wrong access key or secret key." : e.message;
    }
  });
  $("logout").addEventListener("click", logout);
  $("keys").addEventListener("click", manageKeys);
  $("new-bucket").addEventListener("click", createBucket);
  $("bucket-filter").addEventListener("input", renderBuckets);
  $("refresh").addEventListener("click", () => loadList(false));
  $("load-more").addEventListener("click", () => loadList(true));
  $("new-folder").addEventListener("click", newFolder);
  $("settings").addEventListener("click", bucketSettings);
  $("details-close").addEventListener("click", closeDetails);
  $("delete-selected").addEventListener("click", () => deleteKeys([...state.selected]));
  $("clear-selection").addEventListener("click", () => { state.selected.clear(); renderRows(); });
  $("select-all").addEventListener("change", (e) => {
    state.selected = new Set(e.target.checked ? state.items.map((i) => i.key) : []);
    renderRows();
  });
  let searchTimer = null;
  $("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadList(false), 250); });
  $("upload-input").addEventListener("change", (e) => { enqueueUploads([...e.target.files]); e.target.value = ""; });
  const drop = $("drop");
  let depth = 0;
  drop.addEventListener("dragenter", (e) => { e.preventDefault(); depth++; drop.classList.add("dragging"); });
  drop.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; drop.classList.remove("dragging"); } });
  drop.addEventListener("dragover", (e) => e.preventDefault());
  drop.addEventListener("drop", (e) => {
    e.preventDefault(); depth = 0; drop.classList.remove("dragging");
    enqueueUploads([...e.dataTransfer.files]);
  });

  let saved = null;
  try { saved = JSON.parse(sessionStorage.getItem("s3rs-console") || "null"); } catch (_) { /* ignore */ }
  if (saved && saved.token && saved.expires > Date.now()) {
    login(saved.ak, saved.sk, saved.region, true, saved).catch(() => {
      try { sessionStorage.removeItem("s3rs-console"); } catch (_) { /* ignore */ }
      $("login").classList.remove("hidden");
    });
  } else {
    $("login").classList.remove("hidden");
  }
});
