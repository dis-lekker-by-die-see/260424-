"use strict";

const K_HEX = "a84d2154d641c877b43d1771eeea0df4";
const VERIFY_PLAINTEXT = "VAULT_OK";
const MANIFEST_URL = "library/manifest.json";

const $ = (id) => document.getElementById(id);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function deriveKey(password, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: hexToBytes(K_HEX), iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
  return (bytes / 1073741824).toFixed(2) + " GB";
}

function formatDate(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

let KEY = null;
let MANIFEST = null;

async function downloadFile(entry, btn) {
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "⏳";
  $("status").textContent = `Downloading ${entry.name}…`;
  try {
    const parts = [];
    for (let i = 0; i < entry.chunks.length; i++) {
      const c = entry.chunks[i];
      $("status").textContent =
        `Fetching chunk ${i + 1}/${entry.chunks.length} of ${entry.name}…`;
      const resp = await fetch(`library/${c.name}`);
      if (!resp.ok) throw new Error(`Fetch failed: ${c.name}`);
      const ct = await resp.arrayBuffer();
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(c.iv) },
        KEY,
        ct,
      );
      parts.push(pt);
    }
    const blob = new Blob(parts, {
      type: entry.mime || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = entry.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    $("status").textContent = `Downloaded ${entry.name}.`;
  } catch (e) {
    $("status").textContent = `Error: ${e.message || e}`;
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function renderTable() {
  const tbody = document.querySelector("#files tbody");
  tbody.innerHTML = "";
  const rows = [...MANIFEST.files].sort((a, b) =>
    (b.uploaded || "").localeCompare(a.uploaded || ""),
  );
  for (const f of rows) {
    const tr = document.createElement("tr");

    const tdName = document.createElement("td");
    tdName.className = "name";
    tdName.textContent = f.name;

    const tdSize = document.createElement("td");
    tdSize.className = "size";
    tdSize.textContent = formatSize(f.size);

    const tdDate = document.createElement("td");
    tdDate.className = "date";
    tdDate.textContent = formatDate(f.uploaded);

    const tdAct = document.createElement("td");
    tdAct.className = "action";
    const btn = document.createElement("button");
    btn.className = "dl";
    btn.textContent = "⬇️";
    btn.title = "Download";
    btn.addEventListener("click", () => downloadFile(f, btn));
    tdAct.appendChild(btn);

    tr.append(tdName, tdSize, tdDate, tdAct);
    tbody.appendChild(tr);
  }
}

async function unlock(password) {
  const resp = await fetch(MANIFEST_URL, { cache: "no-store" });
  if (!resp.ok) throw new Error("manifest missing");
  const manifest = await resp.json();
  const key = await deriveKey(password, manifest.iterations);
  // Verify
  const iv = hexToBytes(manifest.verify.iv);
  const ct = hexToBytes(manifest.verify.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  if (new TextDecoder().decode(pt) !== VERIFY_PLAINTEXT) throw new Error("bad");
  KEY = key;
  MANIFEST = manifest;
}

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("pw").value;
  if (!pw) return;
  try {
    await unlock(pw);
    $("pw").value = "";
    $("gate").hidden = true;
    $("app").hidden = false;
    renderTable();
  } catch {
    $("pw").value = "";
  }
});
