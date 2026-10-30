const API = "";
const REFRESH_MS = 10000;
const history = [];
let hosts = [];
let events = [];
let selectedHost = "";

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const num = (value, digits = 1) => Number.isFinite(Number(value)) ? Number(value).toFixed(digits) : "—";
const bytes = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  const units = ["B","KB","MB","GB","TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i > 1 ? 1 : 0) + " " + units[i];
};
const timeAgo = (value) => {
  if (!value) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (!Number.isFinite(seconds)) return "—";
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
};
const severity = (value) => {
  const s = String(value || "info").toLowerCase();
  return '<span class="severity ' + esc(s) + '">' + esc(s) + '</span>';
};
const isOnline = (lastSeen) => lastSeen && (Date.now() - new Date(lastSeen).getTime() < 90000);

async function getJson(path) {
  const response = await fetch(API + path, {headers: {"Accept":"application/json"}, cache:"no-store"});
  if (!response.ok) throw new Error(path + " returned HTTP " + response.status);
  return response.json();
}
function setConnection(ok, message) {
  $("connection-dot").parentElement.classList.toggle("offline", !ok);
  $("connection-label").textContent = message;
}
function renderOverview(summary) {
  const latest = hosts[0]?.metrics || {};
  const cpu = Number(latest.cpu_percent);
  const mem = Number(latest.memory?.percent);
  $("host-count").textContent = summary.monitored_hosts ?? hosts.length;
  $("cpu-value").textContent = num(cpu);
  $("memory-value").textContent = num(mem);
  $("event-count").textContent = events.length;
  $("nav-event-count").textContent = events.length;
  $("cpu-meter").style.width = (Number.isFinite(cpu) ? Math.max(0,Math.min(100,cpu)) : 0) + "%";
  $("memory-meter").style.width = (Number.isFinite(mem) ? Math.max(0,Math.min(100,mem)) : 0) + "%";
  $("memory-foot").textContent = latest.memory ? bytes(latest.memory.available_bytes) + " available" : "Latest host sample";
  const point = {cpu: Number.isFinite(cpu) ? cpu : 0, memory: Number.isFinite(mem) ? mem : 0};
  history.push(point);
  if (history.length > 30) history.shift();
  drawChart();
  $("host-preview").innerHTML = hosts.length ? hosts.slice(0,4).map(host => {
    const online = isOnline(host.last_seen);
    return '<div class="host-row"><div><div class="host-name">' + esc(host.host_id) + '</div><div class="host-meta">Last report ' + esc(timeAgo(host.last_seen)) + '</div></div><span class="status ' + (online ? "online":"stale") + '">' + (online ? "Online":"Stale") + '</span></div>';
  }).join("") : '<div class="empty">No hosts have reported yet.</div>';
  $("overview-events").innerHTML = events.slice(0,6).map(event => '<tr><td><div class="event-name">' + esc(event.event_type) + '</div><div class="event-sub">' + esc(event.message) + '</div></td><td>' + esc(event.host_id) + '</td><td>' + severity(event.severity) + '</td><td>' + esc(timeAgo(event.created_at)) + '</td></tr>').join("") || '<tr><td colspan="4" class="empty">No events received yet.</td></tr>';
}
function drawChart() {
  const canvas = $("resource-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(300, rect.width * dpr);
  canvas.height = 220 * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr,dpr);
  const w = canvas.width/dpr, h = 220, pad = {l:30,r:12,t:12,b:25};
  const cw = w-pad.l-pad.r, ch = h-pad.t-pad.b;
  ctx.clearRect(0,0,w,h);
  ctx.font = "10px system-ui";
  for (let v=0;v<=100;v+=25) {
    const y = pad.t + ch*(1-v/100);
    ctx.strokeStyle = "#26374d"; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(w-pad.r,y); ctx.stroke();
    ctx.fillStyle = "#7890ad"; ctx.fillText(v+"%",2,y+3);
  }
  if (!history.length) return;
  const drawLine = (key,color) => {
    ctx.beginPath();
    history.forEach((p,i) => {
      const x = pad.l + (history.length === 1 ? cw : cw*i/(history.length-1));
      const y = pad.t + ch*(1-Math.max(0,Math.min(100,p[key]))/100);
      if (!i) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    });
    ctx.strokeStyle=color;ctx.lineWidth=2;ctx.lineJoin="round";ctx.stroke();
  };
  drawLine("cpu","#39d4c5"); drawLine("memory","#a78bfa");
}
function renderHosts() {
  $("hosts-grid").innerHTML = hosts.map(host => {
    const m=host.metrics||{}, mem=m.memory||{}, disks=Object.entries(m.disk||{});
    const online=isOnline(host.last_seen);
    const diskMarkup=disks.length ? disks.map(([mount,d]) => '<div class="host-stat"><span>Disk ' + esc(mount) + '</span><strong>' + num(d.percent) + '%</strong></div>').join("") : '<div class="host-stat"><span>Disk</span><strong>—</strong></div>';
    return '<article class="host-card"><div class="host-card-head"><div><h3>' + esc(host.host_id) + '</h3><div class="host-platform">' + esc(m.platform) + '</div></div><span class="status ' + (online?"online":"stale") + '">' + (online?"Online":"Stale") + '</span></div><div class="host-stats"><div class="host-stat"><span>CPU</span><strong>' + num(m.cpu_percent) + '%</strong></div><div class="host-stat"><span>Memory</span><strong>' + num(mem.percent) + '%</strong></div><div class="host-stat"><span>Processes</span><strong>' + esc(m.process_count) + '</strong></div><div class="host-stat"><span>Listening ports</span><strong>' + (m.listening_ports||[]).length + '</strong></div>' + diskMarkup + '</div><div class="host-last">Last report: ' + esc(timeAgo(host.last_seen)) + ' · Uptime: ' + esc(formatUptime(m.uptime_seconds)) + '</div></article>';
  }).join("") || '<div class="panel empty">No monitored hosts found. Check that the agent service is running.</div>';
}
function formatUptime(value) {
  const s=Number(value); if(!Number.isFinite(s)) return "—";
  const d=Math.floor(s/86400), h=Math.floor((s%86400)/3600), m=Math.floor((s%3600)/60);
  return (d?d+"d ":"") + h+"h "+m+"m";
}
function renderEvents() {
  const query=($("event-search")?.value||"").toLowerCase();
  const filter=$("severity-filter")?.value||"all";
  const filtered=events.filter(e => (filter==="all" || e.severity===filter) && [e.message,e.event_type,e.host_id,JSON.stringify(e.details||{})].join(" ").toLowerCase().includes(query));
  $("events-table").innerHTML=filtered.map(e => '<tr><td><div class="event-name">' + esc(e.event_type) + '</div><div class="event-sub">' + esc(e.message) + '</div></td><td>' + esc(e.host_id) + '</td><td>' + severity(e.severity) + '</td><td>' + esc(e.details?.path || e.details?.mountpoint || e.details?.sha256 || "—") + '</td><td>' + esc(timeAgo(e.created_at)) + '</td></tr>').join("") || '<tr><td colspan="5" class="empty">No matching events.</td></tr>';
}
function fillHostSelects() {
  ["process-host","network-host"].forEach(id => {
    const el=$(id), previous=el.value;
    el.innerHTML=hosts.map(h => '<option value="' + esc(h.host_id) + '">' + esc(h.host_id) + '</option>').join("");
    if (hosts.some(h=>h.host_id===previous)) el.value=previous;
  });
  if (!selectedHost && hosts.length) selectedHost=hosts[0].host_id;
}
function selectedMetrics(selectId) {
  const id=$(selectId)?.value || selectedHost;
  return hosts.find(h=>h.host_id===id)?.metrics || {};
}
function renderProcesses() {
  const m=selectedMetrics("process-host"), list=m.processes||[];
  $("process-subtitle").textContent=(m.hostname||"Selected host")+" · "+list.length+" sampled processes";
  $("process-table").innerHTML=list.slice().sort((a,b)=>(b.memory_rss_bytes||0)-(a.memory_rss_bytes||0)).slice(0,200).map(p=>'<tr><td>'+esc(p.pid)+'</td><td>'+esc(p.name)+'</td><td>'+esc(p.username)+'</td><td>'+esc(bytes(p.memory_rss_bytes))+'</td><td title="'+esc(p.exe)+'">'+esc(p.exe||"—")+'</td></tr>').join("")||'<tr><td colspan="5" class="empty">No process data in the latest telemetry.</td></tr>';
}
function renderNetwork() {
  const list=selectedMetrics("network-host").listening_ports||[];
  $("network-table").innerHTML=list.map(item=>{
    const address=item.local_address||"—", port=address.includes(":")?address.slice(address.lastIndexOf(":")+1):"—";
    return '<tr><td>'+esc(address)+'</td><td>'+esc(port)+'</td><td>'+esc(item.pid)+'</td><td>'+esc(item.family)+'</td><td>'+esc(item.type)+'</td></tr>';
  }).join("")||'<tr><td colspan="5" class="empty">No listening-port data in the latest telemetry.</td></tr>';
}
function renderAntivirus() {
  $("antivirus-grid").innerHTML=hosts.map(host=>{
    const av=host.metrics?.antivirus||{};
    const state=(v)=>v===true?'<span class="av-ok">Available</span>':v===false?'<span class="av-no">Not found</span>':'<span>Unknown</span>';
    const daemon=av.clamav_daemon_active===true?'<span class="av-ok">Active</span>':av.clamav_daemon_active===false?'<span class="av-no">Inactive</span>':'<span>Unknown</span>';
    return '<article class="host-card"><div class="host-card-head"><h3>'+esc(host.host_id)+'</h3><span class="status '+(isOnline(host.last_seen)?"online":"stale")+'">'+(isOnline(host.last_seen)?"Online":"Stale")+'</span></div><div class="av-item"><span>clamd</span>'+state(av.clamd)+'</div><div class="av-item"><span>clamscan</span>'+state(av.clamscan)+'</div><div class="av-item"><span>freshclam</span>'+state(av.freshclam)+'</div><div class="av-item"><span>ClamAV daemon</span>'+daemon+'</div></article>';
  }).join("")||'<div class="panel empty">No antivirus telemetry available.</div>';
}
function switchView(name) {
  document.querySelectorAll(".view").forEach(v=>v.classList.toggle("active",v.id==="view-"+name));
  document.querySelectorAll(".nav-link").forEach(v=>v.classList.toggle("active",v.dataset.view===name));
  const titles={overview:"System overview",hosts:"Monitored hosts",events:"Security events",processes:"Running processes",network:"Network ports",antivirus:"Antivirus status"};
  $("page-title").textContent=titles[name]||"System overview";
  if(name==="processes")renderProcesses(); if(name==="network")renderNetwork();
}
async function refresh() {
  try {
    const [summaryData,hostData,eventData]=await Promise.all([getJson("/api/v1/summary"),getJson("/api/v1/hosts"),getJson("/api/v1/events?limit=100")]);
    hosts=Array.isArray(hostData)?hostData:[];
    events=Array.isArray(eventData)?eventData:[];
    renderOverview(summaryData||{});
    renderHosts(); renderEvents(); fillHostSelects(); renderProcesses(); renderNetwork(); renderAntivirus();
    $("last-updated").textContent=new Date().toLocaleTimeString();
    setConnection(true,"API connected");
  } catch(error) {
    setConnection(false,"API unavailable");
    console.error("SentinelX dashboard refresh failed:",error);
  }
}
document.querySelectorAll("[data-view]").forEach(link=>link.addEventListener("click",e=>{e.preventDefault();const name=link.dataset.view;switchView(name);history.replaceState(null,"","#"+name);}));
$("refresh-btn").addEventListener("click",refresh);
$("event-search").addEventListener("input",renderEvents);
$("severity-filter").addEventListener("change",renderEvents);
$("process-host").addEventListener("change",renderProcesses);
$("network-host").addEventListener("change",renderNetwork);
window.addEventListener("resize",drawChart);
refresh();
setInterval(refresh,REFRESH_MS);