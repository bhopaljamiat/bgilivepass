/* BGI Live Pass â€” Master Admin extensions
   Gates & capacity, access profiles, per-pass permissions, live command center, demo simulator.
   Loaded after the inline script in admin.html (shares its globals: $, api, zones, events, toast, openModal...). */
(function () {
  "use strict";
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  window.gatesAll = [];
  window.profilesAll = [];
  const loadGatesAll = async () => (window.gatesAll = (await api("/gates")).gates || []);
  const loadProfilesAll = async () => (window.profilesAll = (await api("/profiles")).profiles || []);
  const p2 = (n) => String(n).padStart(2, "0");
  const toLocal = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}T${p2(d.getHours())}:${p2(d.getMinutes())}`;
  };
  const fromLocal = (v) => (v ? new Date(v).toISOString() : null);
  const DIR = { in: "ENTRY", out: "EXIT", both: "IN + OUT" };

  /* ---------- styles ---------- */
  document.head.insertAdjacentHTML("beforeend", `<style>
    .mx { width: 100%; font-size: 13px; }
    .mx td { vertical-align: middle; }
    .mx select { width: 150px; padding: 6px 8px; }
    .mx .mx-more { display: flex; gap: 6px; flex-wrap: wrap; }
    .mx .mx-more input { width: 170px; padding: 5px 8px; font-size: 12px; }
    .mx .mx-note { width: 200px !important; }
    .chip { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 10px; font-weight: 700; margin-left: 6px; }
    .chip.in { background: rgba(62,207,174,0.16); color: var(--acc); }
    .chip.out { background: rgba(240,180,41,0.16); color: var(--acc2); }
    .chip.both { background: rgba(96,165,250,0.16); color: var(--blue); }
    .chip.closed { background: rgba(240,86,106,0.16); color: var(--danger); }
    .grid2 { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px; }
    .zc { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
    .zc .big { font-size: 38px; font-weight: 800; line-height: 1; }
    .zc .name { font-weight: 700; margin-bottom: 8px; }
    .bar { height: 10px; background: var(--card2); border-radius: 8px; overflow: hidden; margin: 10px 0; }
    .bar i { display: block; height: 100%; background: var(--acc); border-radius: 8px; transition: width .4s; }
    .bar i.amber { background: var(--acc2); } .bar i.red { background: var(--danger); }
    .gl { font-size: 12px; color: var(--mut); display: flex; justify-content: space-between; padding: 3px 0; border-top: 1px dashed var(--line); }
    .alert { padding: 9px 14px; border-radius: 10px; margin-bottom: 8px; font-size: 13px; font-weight: 600; }
    .alert.red { background: rgba(240,86,106,0.14); color: var(--danger); border: 1px solid var(--danger); }
    .alert.amber { background: rgba(240,180,41,0.14); color: var(--acc2); border: 1px solid var(--acc2); }
    .hbars { display: flex; align-items: flex-end; gap: 6px; height: 110px; }
    .hbars .c { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; gap: 2px; font-size: 10px; color: var(--mut); }
    .hbars .c div.b { width: 100%; display: flex; gap: 2px; align-items: flex-end; flex: 1; }
    .hbars .c i { flex: 1; border-radius: 3px 3px 0 0; min-height: 1px; }
    .hbars .e { background: var(--acc); } .hbars .x { background: var(--acc2); }
    .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }
    .eff-ok { color: var(--acc); font-weight: 700; } .eff-no { color: var(--danger); font-weight: 700; }
    .live-dot { display: inline-block; width: 9px; height: 9px; background: var(--danger); border-radius: 50%; margin-right: 6px; animation: blink 1.2s infinite; }
    @keyframes blink { 50% { opacity: .25; } }
    #v-live:fullscreen { background: var(--bg); padding: 20px; overflow: auto; }
    .foot { text-align: center; color: var(--mut); font-size: 12px; margin: 28px 0 8px; }
  </style>`);

  /* ---------- wide modal + view hooks ---------- */
  const _openModal = window.openModal;
  window.openModal = function (html) { $("#modalBox").style.maxWidth = ""; _openModal(html); };
  const openWide = (html) => { _openModal(html); $("#modalBox").style.maxWidth = "900px"; };

  /* ---------- permission matrix (zone/gate allow-deny grid) ---------- */
  function matrixHTML(rules) {
    const find = (type, id) => (rules || []).find((r) => r.targetType === type && r.targetId === id);
    const row = (type, id, label, sub, d) => {
      const r = find(type, id);
      const st = r ? r.effect : "";
      return `<tr class="mx-row" data-type="${type}" data-id="${id}">
        <td style="padding-left:${sub ? 28 : 10}px">${sub ? "â†³ " : ""}${sub ? esc(label) : "<b>" + esc(label) + "</b>"}${d ? `<span class="chip ${d}">${DIR[d]}</span>` : ""}</td>
        <td><select class="mx-eff" onchange="mxToggle(this)">
          <option value="" ${st === "" ? "selected" : ""}>â€” not set</option>
          <option value="allow" ${st === "allow" ? "selected" : ""}>âœ… Allow</option>
          <option value="deny" ${st === "deny" ? "selected" : ""}>â›” Deny</option></select></td>
        <td><div class="mx-more" style="${st ? "" : "display:none"}">
          <input type="datetime-local" class="mx-from" value="${toLocal(r && r.validFrom)}" title="Valid from (optional)">
          <input type="datetime-local" class="mx-to" value="${toLocal(r && r.validTo)}" title="Valid until (optional)">
          <input class="mx-note" placeholder="Note (guard sees this on deny)" value="${esc(r && r.note)}"></div></td></tr>`;
    };
    const out = [];
    zones.forEach((z) => {
      out.push(row("zone", z.id, z.name, false, ""));
      gatesAll.filter((g) => g.zoneId === z.id).forEach((g) => out.push(row("gate", g.id, g.name, true, g.direction)));
    });
    if (!out.length) return `<div class="empty">Create zones and gates first (Gates tab).</div>`;
    return `<div class="scroll"><table class="mx" id="mxTable"><tr><th>Zone / Gate</th><th>Permission</th><th>Time limit &amp; note (optional)</th></tr>${out.join("")}</table></div>
      <div class="mut" style="margin-top:6px">A gate rule beats its zone rule. "Not set" = no opinion (falls back to the profile; if nothing allows it, entry is denied).</div>`;
  }
  window.mxToggle = (sel) => {
    const more = sel.closest("tr").querySelector(".mx-more");
    more.style.display = sel.value ? "" : "none";
  };
  function readMatrix() {
    return [...document.querySelectorAll("#mxTable .mx-row")].map((tr) => {
      const eff = tr.querySelector(".mx-eff").value;
      if (!eff) return null;
      return {
        target_type: tr.dataset.type, target_id: Number(tr.dataset.id), effect: eff,
        valid_from: fromLocal(tr.querySelector(".mx-from").value), valid_to: fromLocal(tr.querySelector(".mx-to").value),
        note: tr.querySelector(".mx-note").value.trim(),
      };
    }).filter(Boolean);
  }

  /* ---------- new sections + nav ---------- */
  document.querySelector("main").insertAdjacentHTML("beforeend",
    `<section id="v-live" style="display:none"></section><section id="v-gates" style="display:none"></section><section id="v-profiles" style="display:none"></section>
     <div class="foot">Developed by Chartered Softwares</div>`);
  const nav = document.querySelector("nav");
  const mkBtn = (view, label) => {
    const b = document.createElement("button");
    b.dataset.view = view; b.textContent = label;
    b.addEventListener("click", () => switchView(view));
    return b;
  };
  nav.querySelector('[data-view="dashboard"]').after(mkBtn("live", "ðŸ”´ Command Center"));
  nav.querySelector('[data-view="zones"]').after(mkBtn("gates", "Gates"), mkBtn("profiles", "Access Profiles"));

  const _switch = window.switchView;
  window.switchView = function (v) {
    if (v !== "live") stopSim();
    _switch(v);
    if (v === "live") renderLive();
    if (v === "gates") renderGates();
    if (v === "profiles") renderProfiles();
  };

  /* ---------- Gates view ---------- */
  async function renderGates() {
    await loadZones(true);
    await loadGatesAll();
    const block = (z) => {
      const rows = gatesAll.filter((g) => g.zoneId === z.id).map((g) => `<tr>
        <td><b>${esc(g.name)}</b>${g.status === "closed" ? '<span class="chip closed">CLOSED</span>' : ""}</td>
        <td><span class="chip ${g.direction}" style="margin:0">${DIR[g.direction]}</span></td>
        <td class="flex"><button class="btn ghost sm" onclick="gateEdit(${g.id})">Edit</button>
        <button class="btn ghost sm" onclick="gateToggle(${g.id},'${g.status}')">${g.status === "open" ? "Close gate" : "Open gate"}</button>
        <button class="btn danger sm" onclick="gateDel(${g.id})">Delete</button></td></tr>`).join("");
      return `<div class="panel"><h3><span>${esc(z.name)}</span><span class="flex"><label style="margin:0">Capacity</label>
        <input id="cap-${z.id}" type="number" min="0" value="${z.capacity || 0}" style="width:90px"><button class="btn sm" onclick="zoneCap(${z.id})">Save</button>
        <span class="mut">0 = unlimited</span></span></h3>
        <table><tr><th>Gate</th><th>Direction</th><th>Actions</th></tr>${rows || `<tr><td colspan="3" class="empty">No gates yet</td></tr>`}</table>
        <div class="row" style="margin-top:12px"><div><label>New gate name</label><input id="gn-${z.id}" placeholder="e.g. Gate 1"></div>
        <div><label>Direction</label><select id="gd-${z.id}"><option value="both">Entry + Exit</option><option value="in">Entry only</option><option value="out">Exit only</option></select></div>
        <div style="flex:0"><button class="btn" onclick="gateAdd(${z.id})">+ Add gate</button></div></div></div>`;
    };
    $("#v-gates").innerHTML = `<div class="panel"><h3>Zones, capacity &amp; gates</h3>
      <div class="mut">Set how many people each zone can hold, and add the gates (entry / exit / both) that guards will use. Add zones in the Zones tab.</div></div>` +
      (zones.map(block).join("") || `<div class="panel"><div class="empty">No zones yet â€” add one in the Zones tab.</div></div>`);
  }
  window.zoneCap = async (id) => {
    try { await api("/zones/" + id, { method: "PUT", body: { capacity: Number($("#cap-" + id).value) || 0 } }); toast("Capacity saved"); renderGates(); }
    catch (e) { toast(e.message, true); }
  };
  window.gateAdd = async (zid) => {
    const name = $("#gn-" + zid).value.trim();
    if (!name) return toast("Gate name required", true);
    try { await api("/gates", { method: "POST", body: { zone_id: zid, name, direction: $("#gd-" + zid).value } }); toast("Gate added"); renderGates(); }
    catch (e) { toast(e.message, true); }
  };
  window.gateToggle = async (id, st) => {
    try { await api("/gates/" + id, { method: "PUT", body: { status: st === "open" ? "closed" : "open" } }); renderGates(); }
    catch (e) { toast(e.message, true); }
  };
  window.gateDel = async (id) => {
    if (!confirm("Delete this gate? Guards assigned to it will be unassigned.")) return;
    try { await api("/gates/" + id, { method: "DELETE" }); toast("Gate deleted"); renderGates(); }
    catch (e) { toast(e.message, true); }
  };
  window.gateEdit = (id) => {
    const g = gatesAll.find((x) => x.id === id);
    const zo = zones.map((z) => `<option value="${z.id}" ${z.id === g.zoneId ? "selected" : ""}>${esc(z.name)}</option>`).join("");
    window.openModal(`<h3>Edit Gate</h3>
      <div class="f"><label>Name</label><input id="geName" value="${esc(g.name)}"></div>
      <div class="f"><label>Zone</label><select id="geZone">${zo}</select></div>
      <div class="f"><label>Direction</label><select id="geDir">
        ${["both", "in", "out"].map((d) => `<option value="${d}" ${g.direction === d ? "selected" : ""}>${{ both: "Entry + Exit", in: "Entry only", out: "Exit only" }[d]}</option>`).join("")}</select></div>
      <div class="flex"><button class="btn" onclick="gateSave(${id})">Save</button><button class="btn ghost" onclick="closeModal()">Cancel</button></div>`);
  };
  window.gateSave = async (id) => {
    try {
      await api("/gates/" + id, { method: "PUT", body: { name: $("#geName").value, zone_id: Number($("#geZone").value), direction: $("#geDir").value } });
      closeModal(); toast("Gate updated"); renderGates();
    } catch (e) { toast(e.message, true); }
  };

  /* ---------- Access Profiles view ---------- */
  async function renderProfiles() {
    await loadZones(true);
    await loadGatesAll();
    await loadProfilesAll();
    const cards = profilesAll.map((p) => `<div class="zc"><div class="name"><span class="dot" style="background:${esc(p.color || "#3b82f6")}"></span>${esc(p.name)}</div>
      <div class="mut">${esc(p.description || "")}</div>
      <div style="margin:10px 0">${p.ruleCount} rule(s) Â· ${p.passCount} pass(es)</div>
      <div class="flex"><button class="btn ghost sm" onclick="profEdit(${p.id})">Edit permissions</button><button class="btn danger sm" onclick="profDel(${p.id})">Delete</button></div></div>`).join("");
    $("#v-profiles").innerHTML = `<div class="panel"><h3><span>Access Profiles</span><button class="btn sm" onclick="profEdit(0)">+ New Profile</button></h3>
      <div class="mut">A profile is a permission template (e.g. General, Family, VIP, Volunteer): which zones and gates it may use. Give a profile to passes, then override per pass when someone is special.</div></div>
      ${cards ? `<div class="grid2">${cards}</div>` : `<div class="panel"><div class="empty">No profiles yet. Create one to start.</div></div>`}`;
  }
  window.profEdit = async (id) => {
    let p = { name: "", description: "", color: "#3b82f6" }, rules = [];
    if (id) {
      p = profilesAll.find((x) => x.id === id);
      rules = (await api("/access/profile/" + id)).rules;
    }
    openWide(`<h3>${id ? "Edit" : "New"} Access Profile</h3>
      <div class="row" style="margin-bottom:12px"><div><label>Name</label><input id="pfName" value="${esc(p.name)}"></div>
      <div style="flex:2"><label>Description</label><input id="pfDesc" value="${esc(p.description || "")}"></div>
      <div style="flex:0;min-width:70px"><label>Colour</label><input id="pfColor" type="color" value="${esc(p.color || "#3b82f6")}" style="padding:2px;height:38px"></div></div>
      ${matrixHTML(rules)}
      <div class="flex" style="margin-top:14px"><button class="btn" onclick="profSave(${id})">Save</button><button class="btn ghost" onclick="closeModal()">Cancel</button></div>`);
  };
  window.profSave = async (id) => {
    const body = { name: $("#pfName").value.trim(), description: $("#pfDesc").value, color: $("#pfColor").value, rules: readMatrix() };
    if (!body.name) return toast("Profile name required", true);
    try {
      await api(id ? "/profiles/" + id : "/profiles", { method: id ? "PUT" : "POST", body });
      closeModal(); toast("Profile saved"); renderProfiles();
    } catch (e) { toast(e.message, true); }
  };
  window.profDel = async (id) => {
    if (!confirm("Delete this profile? Passes using it will have no profile (only their own rules apply).")) return;
    try { await api("/profiles/" + id, { method: "DELETE" }); toast("Profile deleted"); renderProfiles(); }
    catch (e) { toast(e.message, true); }
  };

  /* ---------- per-pass access editor (the admin's control panel for ONE mumin) ---------- */
  const effHTML = (matrix) => {
    const rows = matrix.map((m) => `<tr><td>${esc(m.zoneName || "")}</td><td>${esc(m.gateName)}<span class="chip ${m.direction}">${DIR[m.direction]}</span>${m.gateStatus === "closed" ? '<span class="chip closed">CLOSED</span>' : ""}</td>
      <td>${m.allowed ? `<span class="eff-ok">âœ… Allowed</span> <span class="mut">${esc(m.via)}</span>` : `<span class="eff-no">â›” Denied</span> <span class="mut">${esc(m.message)}</span>`}</td></tr>`).join("");
    return `<div class="scroll"><table><tr><th>Zone</th><th>Gate</th><th>Entry right now</th></tr>${rows || `<tr><td colspan="3" class="empty">No gates configured</td></tr>`}</table></div>`;
  };
  window.passAccess = async (id) => {
    await loadZones(true); await loadGatesAll(); await loadProfilesAll();
    const d = await api("/access/pass/" + id + "/effective");
    const p = d.pass;
    const popts = `<option value="">â€” No profile â€”</option>` + profilesAll.map((x) => `<option value="${x.id}" ${p.profileId === x.id ? "selected" : ""}>${esc(x.name)}</option>`).join("");
    openWide(`<h3>Access â€” ${esc(p.name)} <span class="mut">(${esc(p.passNo)})</span></h3>
      <div class="row" style="margin-bottom:12px">
        <div><label>Profile (template)</label><select id="paProfile">${popts}</select></div>
        <div><label>Mode</label><select id="paMode"><option value="rules" ${p.accessMode === "rules" ? "selected" : ""}>Profile + rules below</option><option value="all" ${p.accessMode === "all" ? "selected" : ""}>Open: all zones &amp; gates</option></select></div>
        <div><label>People on this pass</label><input id="paMembers" type="number" min="1" value="${p.members || 1}"></div>
        <div><label>Max entries (blank = unlimited)</label><input id="paMax" type="number" min="1" value="${p.maxEntries == null ? "" : p.maxEntries}"></div></div>
      <div class="row" style="margin-bottom:14px">
        <div><label>Pass valid from (optional)</label><input id="paFrom" type="datetime-local" value="${toLocal(p.validFrom)}"></div>
        <div><label>Pass valid until (optional)</label><input id="paTo" type="datetime-local" value="${toLocal(p.validTo)}"></div></div>
      <h3 style="font-size:14px;margin-bottom:8px">Rules for this pass only <span class="mut">(override the profile)</span></h3>
      ${matrixHTML(d.rules.filter((r) => r.scopeType === "pass"))}
      <div class="flex" style="margin:14px 0"><button class="btn" onclick="passAccessSave(${id})">Save access</button><button class="btn ghost" onclick="closeModal()">Close</button></div>
      <h3 style="font-size:14px;margin:6px 0 8px">What this pass can do right now</h3>${effHTML(d.matrix)}`);
  };
  window.passAccessSave = async (id) => {
    try {
      await api("/access/pass/" + id, { method: "PUT", body: {
        pass: { profile_id: $("#paProfile").value || null, access_mode: $("#paMode").value, members: Number($("#paMembers").value) || 1,
          max_entries: $("#paMax").value || null, valid_from: fromLocal($("#paFrom").value), valid_to: fromLocal($("#paTo").value) },
        rules: readMatrix(),
      } });
      toast("Access saved");
      window.passAccess(id);
      if (typeof loadPasses === "function") loadPasses();
    } catch (e) { toast(e.message, true); }
  };

  /* ---------- bulk access ---------- */
  window.bulkAccess = async () => {
    await loadZones(true); await loadGatesAll(); await loadProfilesAll();
    const eopts = events.map((e) => `<option value="${e.id}" ${e.status === "active" ? "selected" : ""}>${esc(e.name)}</option>`).join("");
    const popts = profilesAll.map((x) => `<option value="${x.id}">${esc(x.name)}</option>`).join("");
    openWide(`<h3>Bulk Access</h3><div class="mut" style="margin-bottom:12px">Change access for many passes at once.</div>
      <div class="row" style="margin-bottom:12px"><div><label>Event</label><select id="baEvent">${eopts}</select></div>
        <div><label>Only this group (optional, exact name)</label><input id="baGroup" placeholder="e.g. Indore"></div></div>
      <div class="row" style="margin-bottom:12px">
        <div><label>Profile</label><select id="baProfile"><option value="__keep">â€” keep as is â€”</option><option value="">Remove profile</option>${popts}</select></div>
        <div><label>Mode</label><select id="baMode"><option value="__keep">â€” keep as is â€”</option><option value="rules">Profile + rules</option><option value="all">Open: all zones &amp; gates</option></select></div>
        <div><label>Max entries</label><input id="baMax" type="number" min="1" placeholder="keep as is"></div>
        <div><label>Pass-specific rules</label><select id="baRulesMode"><option value="">Don't change</option><option value="add">Add the rules below</option><option value="replace">Replace with the rules below</option><option value="clear">Clear all pass-specific rules</option></select></div></div>
      ${matrixHTML([])}
      <div class="flex" style="margin-top:14px"><button class="btn" onclick="bulkAccessSave()">Apply to passes</button><button class="btn ghost" onclick="closeModal()">Cancel</button></div>`);
  };
  window.bulkAccessSave = async () => {
    const apply = {};
    if ($("#baProfile").value !== "__keep") apply.profile_id = $("#baProfile").value || null;
    if ($("#baMode").value !== "__keep") apply.access_mode = $("#baMode").value;
    if ($("#baMax").value) apply.max_entries = $("#baMax").value;
    const filter = { event_id: Number($("#baEvent").value) };
    if ($("#baGroup").value.trim()) filter.group = $("#baGroup").value.trim();
    const rules_mode = $("#baRulesMode").value;
    const rules = readMatrix();
    if ((rules_mode === "add" || rules_mode === "replace") && !rules.length) return toast("Set at least one rule in the grid", true);
    if (!confirm("Apply these changes to all matching passes?")) return;
    try {
      const d = await api("/access/bulk", { method: "POST", body: { filter, apply, rules_mode: rules_mode || undefined, rules } });
      closeModal(); toast(d.updated + " pass(es) updated");
      if (typeof loadPasses === "function") loadPasses();
    } catch (e) { toast(e.message, true); }
  };

  /* ---------- guard: assign gate ---------- */
  window.editUser = async (id) => {
    await loadZones(true); await loadGatesAll();
    const d = await api("/users");
    const u = d.users.find((x) => x.id === id);
    if (!u) return;
    const zopts = `<option value="">No zone</option>` + zones.map((z) => `<option value="${z.id}" ${u.zone_id === z.id ? "selected" : ""}>${esc(z.name)}</option>`).join("");
    window.openModal(`<h3>Edit User â€” ${esc(u.name)}</h3>
      <div class="f"><label>Name</label><input id="muName" value="${esc(u.name)}"></div>
      <div class="f"><label>Phone</label><input id="muPhone" value="${esc(u.phone || "")}"></div>
      <div class="f"><label>Zone</label><select id="muZone">${zopts}</select></div>
      ${u.role === "guard" ? `<div class="f"><label>Gate (fixed gate for this guard; blank = guard picks)</label><select id="muGate"></select></div>` : ""}
      <div class="f"><label>Status</label><select id="muStatus"><option value="active" ${u.status === "active" ? "selected" : ""}>active</option><option value="disabled" ${u.status === "disabled" ? "selected" : ""}>disabled</option></select></div>
      <div class="f"><label>New Password (leave blank to keep unchanged)</label><input id="muPass" type="password" placeholder="optional"></div>
      <div class="flex"><button class="btn" onclick="saveUser(${id})">Save</button><button class="btn ghost" onclick="closeModal()">Cancel</button></div>`);
    const fill = () => {
      const g = $("#muGate"); if (!g) return;
      const zid = Number($("#muZone").value) || null;
      const list = gatesAll.filter((x) => !zid || x.zoneId === zid);
      g.innerHTML = `<option value="">â€” Guard picks own gate â€”</option>` + list.map((x) => `<option value="${x.id}" ${u.gate_id === x.id ? "selected" : ""}>${esc(x.name)} Â· ${esc(x.zoneName || "")}</option>`).join("");
    };
    fill();
    $("#muZone").addEventListener("change", fill);
  };
  window.saveUser = async (id) => {
    const body = { name: $("#muName").value, phone: $("#muPhone").value, zone_id: $("#muZone").value || null, status: $("#muStatus").value };
    if ($("#muGate")) body.gate_id = $("#muGate").value || null;
    if ($("#muPass").value) body.password = $("#muPass").value;
    try { await api("/users/" + id, { method: "PUT", body }); closeModal(); toast("User updated"); loadUsers(); }
    catch (e) { toast(e.message, true); }
  };

  /* ---------- Command Center (live) + demo simulator ---------- */
  let liveTimer = null, simTimer = null, simBusy = false;
  function stopSim() {
    if (simTimer) { clearInterval(simTimer); simTimer = null; }
    if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
  }
  const RESULT = {
    ok: "OK", no_permission: "No access", already_in: "Already in", no_entry: "Not inside", zone_full: "Zone full", blocked: "BLOCKED",
    expired: "Expired", not_yet_valid: "Not valid yet", outside_time: "Wrong time", max_entries: "Entry limit", gate_closed: "Gate closed",
    event_closed: "Event closed", not_found: "Not found",
  };

  async function renderLive() {
    await loadEvents();
    $("#v-live").innerHTML = `<div class="panel"><h3><span><span class="live-dot"></span>Command Center <span class="mut" id="lvEvent"></span></span>
        <span class="flex"><select id="lvEventSel" style="width:220px"><option value="">Auto (active event)</option>${events.map((e) => `<option value="${e.id}">${esc(e.name)}</option>`).join("")}</select>
        <button class="btn ghost sm" id="lvFs">â›¶ Fullscreen</button></span></h3>
      <div class="flex" style="flex-wrap:wrap"><span class="mut">Demo:</span>
        <button class="btn ghost sm" id="dmSeed">Create demo data</button>
        <button class="btn sm" id="dmStart">â–¶ Start crowd simulator</button>
        <button class="btn ghost sm" id="dmStop" style="display:none">â–  Stop simulator</button>
        <button class="btn danger sm" id="dmReset">Remove demo data</button><span class="mut" id="dmState"></span></div></div>
      <div id="lvAlerts"></div><div class="cards" id="lvCards"></div><div class="grid2" id="lvZones"></div>
      <div class="panel" style="margin-top:20px"><h3>Last 12 hours <span class="mut"><span class="dot" style="background:var(--acc)"></span>Entries <span class="dot" style="background:var(--acc2);margin-left:8px"></span>Exits</span></h3><div id="lvHours"></div></div>
      <div class="panel"><h3>Live scans</h3><div class="scroll"><table id="lvRecent"></table></div></div>`;
    $("#lvEventSel").addEventListener("change", refreshLive);
    $("#lvFs").addEventListener("click", () => { const el = $("#v-live"); (document.fullscreenElement ? document.exitFullscreen() : el.requestFullscreen && el.requestFullscreen()); });
    $("#dmSeed").addEventListener("click", async () => {
      try { const d = await api("/demo/seed", { method: "POST" }); toast(d.already ? "Demo data already exists" : `Demo ready: ${d.zones} zones, ${d.gates} gates, ${d.passes} passes`); await renderLive(); }
      catch (e) { toast(e.message, true); }
    });
    $("#dmStart").addEventListener("click", startSim);
    $("#dmStop").addEventListener("click", () => { stopSimOnly(); });
    $("#dmReset").addEventListener("click", async () => {
      if (!confirm("Remove ALL demo data (zones, gates, passes, scans named '(Demo)')? Your real data is not touched.")) return;
      stopSimOnly();
      try { const d = await api("/demo", { method: "DELETE" }); toast("Demo data removed (" + d.passesRemoved + " passes)"); await renderLive(); }
      catch (e) { toast(e.message, true); }
    });
    await refreshLive();
    if (liveTimer) clearInterval(liveTimer);
    liveTimer = setInterval(refreshLive, 3000);
  }

  function stopSimOnly() {
    if (simTimer) { clearInterval(simTimer); simTimer = null; }
    if ($("#dmStop")) { $("#dmStop").style.display = "none"; $("#dmStart").style.display = ""; $("#dmState").textContent = ""; }
  }
  function startSim() {
    if (simTimer) return;
    $("#dmStart").style.display = "none"; $("#dmStop").style.display = "";
    $("#dmState").textContent = "Simulator running â€” fake guards are scanning at all gatesâ€¦";
    const step = async () => {
      if (simBusy) return;
      simBusy = true;
      try { await api("/demo/step", { method: "POST", body: { n: 3 } }); }
      catch (e) { stopSimOnly(); toast(e.message, true); }
      simBusy = false;
    };
    step();
    simTimer = setInterval(step, 1500);
  }

  async function refreshLive() {
    if (currentView !== "live" || !$("#lvCards")) return;
    try {
      const q = $("#lvEventSel").value ? "?event_id=" + $("#lvEventSel").value : "";
      const d = await api("/live" + q);
      if (!d.event) {
        $("#lvCards").innerHTML = `<div class="panel" style="grid-column:1/-1"><div class="empty">No event yet. Create an event, or press "Create demo data".</div></div>`;
        $("#lvZones").innerHTML = ""; $("#lvAlerts").innerHTML = ""; $("#lvRecent").innerHTML = ""; $("#lvHours").innerHTML = "";
        return;
      }
      $("#lvEvent").textContent = "Â· " + d.event.name;
      $("#lvAlerts").innerHTML = d.alerts.map((a) => `<div class="alert ${a.level}">${a.level === "red" ? "ðŸš¨" : "âš ï¸"} ${esc(a.text)}</div>`).join("");
      const t = d.totals;
      $("#lvCards").innerHTML = `
        <div class="stat g"><div class="n">${t.passes}</div><div class="l">Total passes</div></div>
        <div class="stat b"><div class="n">${t.passesInside}</div><div class="l">Passes inside now</div></div>
        <div class="stat g"><div class="n">${t.entries24h}</div><div class="l">Entries (24h, people)</div></div>
        <div class="stat y"><div class="n">${t.exits24h}</div><div class="l">Exits (24h, people)</div></div>
        <div class="stat r"><div class="n">${t.denied24h}</div><div class="l">Denied scans (24h)</div></div>`;
      $("#lvZones").innerHTML = d.zones.map((z) => {
        const cls = z.pct == null ? "" : z.pct >= 100 ? "red" : z.pct >= 80 ? "amber" : "";
        const gl = z.gates.map((g) => `<div class="gl"><span>${esc(g.name)}<span class="chip ${g.direction}">${DIR[g.direction]}</span>${g.status === "closed" ? '<span class="chip closed">CLOSED</span>' : ""}</span>
          <span>âœ… ${g.ok5m} Â· â›” ${g.denied5m} <span class="mut">(5 min)</span></span></div>`).join("");
        return `<div class="zc"><div class="name">${esc(z.name)}</div>
          <div class="big">${z.inside}<span class="mut" style="font-size:16px;font-weight:600">${z.capacity ? " / " + z.capacity : " inside"}</span></div>
          ${z.capacity ? `<div class="bar"><i class="${cls}" style="width:${Math.min(100, z.pct)}%"></i></div><div class="mut">${z.pct}% full</div>` : `<div class="mut" style="margin:10px 0">No capacity limit</div>`}
          ${gl}</div>`;
      }).join("") || `<div class="panel" style="grid-column:1/-1"><div class="empty">No zones</div></div>`;
      const mx = Math.max(1, ...d.hourly.map((h) => Math.max(h.entries, h.exits)));
      $("#lvHours").innerHTML = d.hourly.length
        ? `<div class="hbars">${d.hourly.map((h) => `<div class="c"><div class="b"><i class="e" style="height:${(h.entries / mx) * 100}%" title="Entries ${h.entries}"></i><i class="x" style="height:${(h.exits / mx) * 100}%" title="Exits ${h.exits}"></i></div>${new Date(h.hour).getHours()}:00</div>`).join("")}</div>`
        : `<div class="empty">No activity yet</div>`;
      $("#lvRecent").innerHTML = `<tr><th>Time</th><th>Mumin</th><th>Pass</th><th>Gate</th><th>Type</th><th>Result</th></tr>` +
        (d.recent.map((s) => `<tr><td class="mut">${new Date(s.createdAt).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</td>
          <td>${esc(s.name || "â€”")}${s.members > 1 ? ` <span class="mut">Ã—${s.members}</span>` : ""}</td><td style="font-family:monospace">${esc(s.passNo || "â€”")}</td><td>${esc(s.gate || "â€”")}</td>
          <td>${s.type === "entry" ? "â¬‡ Entry" : "â¬† Exit"}</td>
          <td><span class="pill ${s.result === "ok" ? "ok" : "failed"}">${RESULT[s.result] || esc(s.result)}</span></td></tr>`).join("") || `<tr><td colspan="6" class="empty">No scans yet</td></tr>`);
    } catch (e) { console.error(e); }
  }

  /* make sure gate names are available when the Users table is drawn */
  const _loadUsers = window.loadUsers;
  window.loadUsers = async function () { try { await loadGatesAll(); } catch {} return _loadUsers(); };
})();
