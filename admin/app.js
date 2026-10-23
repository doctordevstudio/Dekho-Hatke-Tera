const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", "x-requested-with": "dh" },
    ...opts,
  });
  if (res.status === 401) { showLogin(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res.json();
}

function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
}
function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  loadUsers();
}

$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("/admin/api/login", { method: "POST", body: JSON.stringify({ u: f.get("u"), p: f.get("p") }) });
    showApp();
  } catch (err) {
    $("#loginErr").textContent = err.message || "Login failed";
  }
});
$("#logoutBtn").addEventListener("click", async () => { await api("/admin/api/logout", { method: "POST" }); showLogin(); });

$$(".navbtn[data-tab]").forEach((b) =>
  b.addEventListener("click", () => {
    $$(".navbtn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $$(".tab").forEach((t) => t.classList.add("hidden"));
    $("#tab-" + b.dataset.tab).classList.remove("hidden");
    if (b.dataset.tab === "devices") loadDevices();
    if (b.dataset.tab === "messages" || b.dataset.tab === "settings") loadSettings();
  })
);

function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleString() : "—"; }

async function loadUsers(q = "") {
  const rows = await api("/admin/api/users?q=" + encodeURIComponent(q));
  $("#userRows").innerHTML = rows.map(r => `
    <tr data-key="${r.key}">
      <td>${esc(r.name || "")}</td><td>${esc(r.key)}</td><td>${esc(r.plan || "")}</td>
      <td>${fmtDate(r.expires_at)}</td><td>${r.devices}</td><td>${fmtDate(r.last_seen)}</td>
      <td><span class="badge ${r.blocked ? "bad" : "good"}">${r.blocked ? "Blocked" : "Active"}</span></td>
    </tr>`).join("");
  $$("#userRows tr").forEach(tr => tr.addEventListener("click", () => openUser(tr.dataset.key)));
}
$("#userSearchBtn").addEventListener("click", () => loadUsers($("#userSearch").value.trim()));
$("#userSearch").addEventListener("keydown", e => { if (e.key === "Enter") loadUsers(e.target.value.trim()); });

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

async function openUser(key) {
  const d = await api("/admin/api/user/" + encodeURIComponent(key));
  const u = d.user;
  const evts = d.events.map(e => `
    <div class="evt">
      <b>${e.type === "watch" ? "▶ Watched" : "⬇ Downloaded"}</b> · ${fmtDate(e.ts)}<br>
      <span class="u">${esc(e.url || e.src || "")}</span>${e.name ? ` — ${esc(e.name)}` : ""}
    </div>`).join("") || `<p class="muted">No activity yet.</p>`;
  const devs = Object.entries(d.devices).map(([id, v]) => `${esc(id.slice(0, 12))}… ${v.banned ? "(banned)" : ""}`).join("<br>") || "—";
  $("#userModalBody").innerHTML = `
    <h2>${esc(u.name || "")}</h2>
    <p class="muted">License key: ${esc(key)} · Plan: ${esc(u.plan || "—")} · Expires: ${fmtDate(u.expires_at)}</p>
    <p class="muted">First seen: ${fmtDate(u.first_seen)} · Last seen: ${fmtDate(u.last_seen)}</p>
    <p><b>Devices:</b><br>${devs}</p>
    <p>
      ${u.blocked
        ? `<button id="unblockBtn" class="primary">Unblock user</button>`
        : `<button id="blockBtn" class="primary">Block user &amp; ban device</button>`}
    </p>
    <h3>Activity (watched / downloaded)</h3>
    <div style="max-height:260px;overflow:auto">${evts}</div>
  `;
  $("#userModal").classList.remove("hidden");
  $("#blockBtn")?.addEventListener("click", async () => {
    const message = prompt("Message shown to the blocked user:", "Your account has been blocked by the admin.");
    if (message === null) return;
    await api(`/admin/api/user/${encodeURIComponent(key)}/block`, { method: "POST", body: JSON.stringify({ message, ban_device: true }) });
    $("#userModal").classList.add("hidden"); loadUsers();
  });
  $("#unblockBtn")?.addEventListener("click", async () => {
    await api(`/admin/api/user/${encodeURIComponent(key)}/unblock`, { method: "POST" });
    $("#userModal").classList.add("hidden"); loadUsers();
  });
}
$("#closeModal").addEventListener("click", () => $("#userModal").classList.add("hidden"));

async function loadDevices() {
  const rows = await api("/admin/api/devices");
  $("#deviceRows").innerHTML = rows.map(r => `
    <tr>
      <td>${esc(r.id.slice(0, 16))}…</td><td>${esc(r.model || "")}</td><td>${r.fails_total || 0}</td>
      <td>${r.blocked_until > Date.now() / 1000 ? fmtDate(r.blocked_until) : "—"}</td>
      <td>${r.banned ? "🚫" : "—"}</td><td>${r.shadow ? "👻" : "—"}</td>
      <td><button data-release="${r.id}">Release</button>${r.banned ? ` <button data-unban="${r.id}">Unban</button>` : ""}</td>
    </tr>`).join("");
  $$("[data-release]").forEach(b => b.addEventListener("click", async () => {
    await api(`/admin/api/device/${b.dataset.release}/release`, { method: "POST", body: "{}" }); loadDevices();
  }));
  $$("[data-unban]").forEach(b => b.addEventListener("click", async () => {
    await api(`/admin/api/device/${b.dataset.unban}/release`, { method: "POST", body: JSON.stringify({ unban: true }) }); loadDevices();
  }));
}

async function loadSettings() {
  const { settings, messages } = await api("/admin/api/settings");
  $("#m_about").value = messages.about.html || "";
  $("#m_privacy").value = messages.privacy.html || "";
  $("#m_contact").value = messages.contact.html || "";
  $("#m_share").value = messages.share.html || "";
  $("#m_share_url").value = messages.share.button_url || "";

  $("#s_maint_on").checked = !!settings.maintenance.enabled;
  $("#s_maint_msg").value = settings.maintenance.message || "";
  $("#s_maint_code").value = settings.maintenance.status_code || 503;
  $("#s_upd_on").checked = !!settings.update.enabled;
  $("#s_upd_msg").value = settings.update.message || "";
  $("#s_upd_btn").value = settings.update.button_text || "";
  $("#s_upd_url").value = settings.update.url || "";
  $("#s_minvc").value = settings.min_version_code || 1;
  $("#s_tg").value = settings.telegram_url || "";
}

$("#saveMessages").addEventListener("click", async () => {
  await api("/admin/api/settings", { method: "POST", body: JSON.stringify({
    messages: {
      about: { html: $("#m_about").value }, privacy: { html: $("#m_privacy").value },
      contact: { html: $("#m_contact").value }, share: { html: $("#m_share").value, button_url: $("#m_share_url").value },
    }
  })});
  $("#msgSaved").textContent = "Saved ✓"; setTimeout(() => $("#msgSaved").textContent = "", 2000);
});

$("#saveSettings").addEventListener("click", async () => {
  await api("/admin/api/settings", { method: "POST", body: JSON.stringify({
    settings: {
      maintenance: { enabled: $("#s_maint_on").checked, message: $("#s_maint_msg").value, status_code: +$("#s_maint_code").value || 503 },
      update: { enabled: $("#s_upd_on").checked, message: $("#s_upd_msg").value, button_text: $("#s_upd_btn").value, url: $("#s_upd_url").value },
      min_version_code: +$("#s_minvc").value || 1,
      telegram_url: $("#s_tg").value,
    }
  })});
  $("#setSaved").textContent = "Saved ✓"; setTimeout(() => $("#setSaved").textContent = "", 2000);
});

// try to resume session
api("/admin/api/users?q=").then(showApp).catch(() => showLogin());
