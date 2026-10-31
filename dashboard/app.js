const API = "";
const REFRESH_MS = 10000;
const resourceHistory = [];
let hosts = [];
let events = [];
let selectedHost = "";
let diskHistory = [];
let lastDiskHistoryKey = "";
let selectedServiceHost = "";
let hostOffset = 0;
let hostTotal = 0;
let hostSearch = "";
const HOST_PAGE_SIZE = 100;

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
async function loadHostPage() {
  const params = new URLSearchParams({limit:String(HOST_PAGE_SIZE),offset:String(hostOffset)});
  if (hostSearch) params.set("search",hostSearch);
  const response = await fetch(API + "/api/v1/hosts?" + params.toString(), {headers:{"Accept":"application/json"},cache:"no-store"});
  if (!response.ok) throw new Error("Host inventory returned HTTP " + response.status);
  hostTotal = Number(response.headers.get("X-Total-Count") || 0);
  hosts = await response.json();
  const first = hostTotal ? hostOffset + 1 : 0;
  const last = Math.min(hostOffset + hosts.length,hostTotal);
  if ($("host-page-label")) $("host-page-label").textContent = first + "–" + last + " of " + hostTotal + " servers";
  if ($("host-prev")) $("host-prev").disabled = hostOffset <= 0;
  if ($("host-next")) $("host-next").disabled = hostOffset + HOST_PAGE_SIZE >= hostTotal;
}
function setConnection(ok, message) {
  $("connection-dot").parentElement.classList.toggle("offline", !ok);
  $("connection-label").textContent = message;
}
function renderOverview(summary) {
  const latest = summary.latest_hosts?.[0]?.metrics || hosts[0]?.metrics || {};
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
  resourceHistory.push(point);
  if (resourceHistory.length > 30) resourceHistory.shift();
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
  if (!resourceHistory.length) return;
  const drawLine = (key,color) => {
    ctx.beginPath();
    resourceHistory.forEach((p,i) => {
      const x = pad.l + (resourceHistory.length === 1 ? cw : cw*i/(resourceHistory.length-1));
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
    const osName=m.os?.system || (String(m.platform||"").toLowerCase().includes("windows")?"Windows":"Linux");
    const serviceCount=Array.isArray(m.services?.items)?m.services.items.length:"—";
    const protection=m.antivirus?.microsoft_defender?.available
      ? (m.antivirus.microsoft_defender.antivirus_enabled ? "Defender on" : "Defender off")
      : (m.antivirus?.clamd !== undefined ? "ClamAV checked" : "Protection —");
    const diskMarkup=disks.length ? disks.map(([mount,d]) => '<div class="host-stat"><span>Disk ' + esc(mount) + '</span><strong>' + num(d.percent) + '%</strong></div>').join("") : '<div class="host-stat"><span>Disk</span><strong>—</strong></div>';
    return '<article class="host-card"><div class="host-card-head"><div><h3>' + esc(host.host_id) + '</h3><div class="host-platform">' + esc(osName) + ' · ' + esc(m.os?.release || m.platform || "OS details unavailable") + '</div></div><span class="status ' + (online?"online":"stale") + '">' + (online?"Online":"Stale") + '</span></div><div class="host-stats"><div class="host-stat"><span>CPU</span><strong>' + num(m.cpu_percent) + '%</strong></div><div class="host-stat"><span>Memory</span><strong>' + num(mem.percent) + '%</strong></div><div class="host-stat"><span>Processes</span><strong>' + esc(m.process_count) + '</strong></div><div class="host-stat"><span>Listening ports</span><strong>' + (m.listening_ports||[]).length + '</strong></div><div class="host-stat"><span>Services</span><strong>' + esc(serviceCount) + '</strong></div><div class="host-stat"><span>Protection</span><strong>' + esc(protection) + '</strong></div>' + diskMarkup + '</div><div class="host-last">Last report: ' + esc(timeAgo(host.last_seen)) + ' · Uptime: ' + esc(formatUptime(m.uptime_seconds)) + '</div></article>';
  }).join("") || '<div class="panel empty">No monitored hosts found. Check that the agent service is running.</div>';
}
function formatUptime(value) {
  const s=Number(value); if(!Number.isFinite(s)) return "—";
  const d=Math.floor(s/86400), h=Math.floor((s%86400)/3600), m=Math.floor((s%3600)/60);
  return (d?d+"d ":"") + h+"h "+m+"m";
}

function diskStatus(percent) {
  const value = Number(percent);
  if (!Number.isFinite(value)) return {label:"Unknown", cls:"healthy"};
  if (value >= 90) return {label:"Critical", cls:"critical"};
  if (value >= 80) return {label:"Warning", cls:"warning"};
  return {label:"Healthy", cls:"healthy"};
}
function currentDiskSelection() {
  const hostId = $("disk-host")?.value || "";
  const host = hosts.find(item => item.host_id === hostId);
  const disk = host?.metrics?.disk || {};
  const mount = $("disk-mount")?.value || Object.keys(disk)[0] || "";
  return {hostId, host, disk, mount, volume:disk[mount]};
}
function fillDiskSelectors() {
  const hostSelect = $("disk-host"), previousHost = hostSelect.value;
  hostSelect.innerHTML = hosts.map(h => '<option value="' + esc(h.host_id) + '">' + esc(h.host_id) + '</option>').join("");
  if (hosts.some(h => h.host_id === previousHost)) hostSelect.value = previousHost;
  const selectedHostId = hostSelect.value;
  const host = hosts.find(h => h.host_id === selectedHostId);
  const disk = host?.metrics?.disk || {};
  const mounts = Object.keys(disk).sort();
  const mountSelect = $("disk-mount"), previousMount = mountSelect.value;
  mountSelect.innerHTML = mounts.map(m => '<option value="' + esc(m) + '">' + esc(m) + '</option>').join("");
  if (mounts.includes(previousMount)) mountSelect.value = previousMount;
  return {hostId:selectedHostId, mount:mountSelect.value, host, disk};
}
function renderDiskMonitoring() {
  const selection = fillDiskSelectors();
  const {hostId, mount, host, disk} = selection;
  const volume = disk[mount];
  const entries = Object.entries(disk);
  $("disk-volume-count").textContent = entries.length;
  const status = diskStatus(volume?.percent);
  $("disk-health-badge").textContent = volume ? status.label : "No data";
  $("disk-health-badge").className = "disk-health " + status.cls;
  if (!volume) {
    ["disk-total","disk-used","disk-free","disk-percent","disk-breakdown-used","disk-breakdown-free","disk-last-report"].forEach(id => $(id).textContent = "—");
    $("disk-volume-label").textContent = "No filesystem data for this host";
    $("disk-meter").style.width = "0%";
    $("disk-health-meter").style.width = "0%";
    $("disk-table").innerHTML = '<tr><td colspan="6" class="empty">No disk telemetry is available. Check that the SentinelX agent is running and reporting.</td></tr>';
    $("disk-table-count").textContent = "0 volumes";
    $("disk-history-caption").textContent = "No selected filesystem";
    drawDiskHistoryChart();
    return;
  }
  const percent = Number(volume.percent);
  const safePercent = Math.max(0, Math.min(100, Number.isFinite(percent) ? percent : 0));
  $("disk-total").textContent = bytes(volume.total_bytes);
  $("disk-used").textContent = bytes(volume.used_bytes);
  $("disk-free").textContent = bytes(volume.free_bytes);
  $("disk-percent").textContent = num(percent) + "% used · " + status.label;
  $("disk-volume-label").textContent = hostId + " · " + mount;
  $("disk-breakdown-used").textContent = bytes(volume.used_bytes);
  $("disk-breakdown-free").textContent = bytes(volume.free_bytes);
  $("disk-last-report").textContent = timeAgo(host?.last_seen);
  $("disk-meter").style.width = safePercent + "%";
  $("disk-health-meter").style.width = safePercent + "%";
  const query = ($("disk-search").value || "").toLowerCase();
  const sort = $("disk-sort").value;
  let rows = entries.filter(([path]) => path.toLowerCase().includes(query));
  if (sort === "usage-desc") rows.sort((a,b)=>(Number(b[1].percent)||0)-(Number(a[1].percent)||0));
  else if (sort === "usage-asc") rows.sort((a,b)=>(Number(a[1].percent)||0)-(Number(b[1].percent)||0));
  else rows.sort((a,b)=>a[0].localeCompare(b[0]));
  $("disk-table-count").textContent = rows.length + " volumes";
  $("disk-table").innerHTML = rows.map(([path,data]) => {
    const state = diskStatus(data.percent);
    const value = Math.max(0,Math.min(100,Number(data.percent)||0));
    const active = path === mount ? " selected-volume" : "";
    return '<tr class="disk-row' + active + '" data-mount="' + esc(path) + '" tabindex="0" role="button" aria-label="Inspect ' + esc(path) + '"><td><strong>' + esc(path) + '</strong></td><td>' + esc(bytes(data.used_bytes)) + ' / ' + esc(bytes(data.total_bytes)) + '</td><td>' + esc(bytes(data.free_bytes)) + '</td><td>' + num(data.percent) + '%</td><td><span class="disk-health ' + state.cls + '">' + state.label + '</span></td><td><div class="disk-row-meter"><i style="width:' + value + '%"></i></div></td></tr>';
  }).join("") || '<tr><td colspan="6" class="empty">No mount points match your search.</td></tr>';
}
async function loadDiskHistory() {
  const {hostId, mount} = currentDiskSelection();
  const key = hostId + "|" + mount;
  lastDiskHistoryKey = key;
  if (!hostId || !mount) {
    diskHistory = [];
    drawDiskHistoryChart();
    return;
  }
  $("disk-history-caption").textContent = "Loading recent stored samples…";
  try {
    const result = await getJson("/api/v1/disk-history?host_id=" + encodeURIComponent(hostId) + "&mountpoint=" + encodeURIComponent(mount) + "&limit=120");
    if (lastDiskHistoryKey !== key) return;
    diskHistory = Array.isArray(result.samples) ? result.samples : [];
    $("disk-history-caption").textContent = diskHistory.length + " stored samples · " + hostId + " · " + mount;
    drawDiskHistoryChart();
  } catch (error) {
    $("disk-history-caption").textContent = "Could not load disk history: " + error.message;
    diskHistory = [];
    drawDiskHistoryChart();
  }
}
function drawDiskHistoryChart() {
  const canvas = $("disk-history-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(300, rect.width * dpr);
  canvas.height = 220 * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr,0,0,dpr,0,0);
  const w = canvas.width/dpr, h = 220, pad = {l:34,r:12,t:14,b:27};
  const cw = w-pad.l-pad.r, ch = h-pad.t-pad.b;
  ctx.clearRect(0,0,w,h);
  ctx.font = "10px system-ui";
  for (let v=0;v<=100;v+=20) {
    const y=pad.t+ch*(1-v/100);
    ctx.strokeStyle="#26374d";ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();
    ctx.fillStyle="#7890ad";ctx.fillText(v+"%",2,y+3);
  }
  [[80,"#f5b95c"],[90,"#ff737d"]].forEach(([v,color])=>{
    const y=pad.t+ch*(1-v/100);
    ctx.setLineDash([5,4]);ctx.strokeStyle=color;ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();ctx.setLineDash([]);
  });
  if (!diskHistory.length) {
    ctx.fillStyle="#8fa2bc";ctx.textAlign="center";
    ctx.fillText("Historical samples will appear as telemetry is collected",w/2,h/2);
    return;
  }
  ctx.beginPath();
  diskHistory.forEach((sample,i)=>{
    const x=pad.l+(diskHistory.length===1?cw:cw*i/(diskHistory.length-1));
    const y=pad.t+ch*(1-Math.max(0,Math.min(100,Number(sample.percent)||0))/100);
    if (!i) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  });
  ctx.strokeStyle="#39d4c5";ctx.lineWidth=2.5;ctx.lineJoin="round";ctx.stroke();
  const last=diskHistory[diskHistory.length-1], lastY=pad.t+ch*(1-Math.max(0,Math.min(100,Number(last.percent)||0))/100);
  ctx.fillStyle="#39d4c5";ctx.beginPath();ctx.arc(w-pad.r,lastY,3.5,0,Math.PI*2);ctx.fill();
  ctx.fillStyle="#8fa2bc";ctx.textAlign="left";ctx.fillText("Oldest",pad.l,h-6);
  ctx.textAlign="right";ctx.fillText("Latest",w-pad.r,h-6);
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
    const defender=av.microsoft_defender;
    const state=(v)=>v===true?'<span class="av-ok">Enabled</span>':v===false?'<span class="av-no">Disabled</span>':'<span>Unknown</span>';
    const availability=(v)=>v===true?'<span class="av-ok">Available</span>':v===false?'<span class="av-no">Unavailable</span>':'<span>Unknown</span>';
    let rows="";
    if(defender){
      rows='<div class="av-item"><span>Microsoft Defender collector</span>'+availability(defender.available)+'</div>'+
        '<div class="av-item"><span>Antivirus protection</span>'+state(defender.antivirus_enabled)+'</div>'+
        '<div class="av-item"><span>Real-time protection</span>'+state(defender.real_time_protection_enabled)+'</div>'+
        '<div class="av-item"><span>Signature updated</span><span>'+esc(defender.signature_last_updated||"Unknown")+'</span></div>';
    } else {
      const clamState=(v)=>v===true?'<span class="av-ok">Available</span>':v===false?'<span class="av-no">Not found</span>':'<span>Unknown</span>';
      const daemon=av.clamav_daemon_active===true?'<span class="av-ok">Active</span>':av.clamav_daemon_active===false?'<span class="av-no">Inactive</span>':'<span>Unknown</span>';
      rows='<div class="av-item"><span>clamd</span>'+clamState(av.clamd)+'</div><div class="av-item"><span>clamscan</span>'+clamState(av.clamscan)+'</div><div class="av-item"><span>freshclam</span>'+clamState(av.freshclam)+'</div><div class="av-item"><span>ClamAV daemon</span>'+daemon+'</div>';
    }
    const sec=host.metrics?.security_event_collection;
    const audit=sec ? (sec.available===true?'<span class="av-ok">Available</span>':'<span class="av-no">Unavailable</span>') : '<span>Not reported</span>';
    return '<article class="host-card"><div class="host-card-head"><h3>'+esc(host.host_id)+'</h3><span class="status '+(isOnline(host.last_seen)?"online":"stale")+'">'+(isOnline(host.last_seen)?"Online":"Stale")+'</span></div>'+rows+'<div class="av-item"><span>Security event collector</span>'+audit+'</div></article>';
  }).join("")||'<div class="panel empty">No endpoint protection telemetry available.</div>';
}
function renderServices() {
  const select=$("service-host");
  if(!select)return;
  const windows=hosts.filter(h=>Array.isArray(h.metrics?.services?.items));
  const previous=select.value || selectedServiceHost;
  select.innerHTML=windows.map(h=>'<option value="'+esc(h.host_id)+'">'+esc(h.host_id)+'</option>').join("");
  if(windows.some(h=>h.host_id===previous))select.value=previous;
  selectedServiceHost=select.value||"";
  const host=windows.find(h=>h.host_id===selectedServiceHost);
  const items=host?.metrics?.services?.items||[];
  const query=($("service-search")?.value||"").toLowerCase();
  const filtered=items.filter(s=>[s.name,s.display_name,s.status,s.start_type,s.username].join(" ").toLowerCase().includes(query));
  $("service-subtitle").textContent=host ? (items.length+" services reported · "+timeAgo(host.last_seen)) : "No Windows service inventory is available yet.";
  $("service-count").textContent=filtered.length+" services";
  $("service-table").innerHTML=filtered.map(s=>{
    const status=String(s.status||"unknown").toLowerCase();
    const cls=status==="running"?"av-ok":status==="stopped"?"av-no":"";
    return '<tr><td><strong>'+esc(s.name)+'</strong></td><td>'+esc(s.display_name)+'</td><td><span class="'+cls+'">'+esc(status)+'</span></td><td>'+esc(s.start_type)+'</td><td>'+esc(s.username)+'</td><td>'+esc(s.pid)+'</td></tr>';
  }).join("")||'<tr><td colspan="6" class="empty">'+(host?"No services match this search.":"No Windows service telemetry received.")+'</td></tr>';
}
function switchView(name) {
  document.querySelectorAll(".view").forEach(v=>v.classList.toggle("active",v.id==="view-"+name));
  document.querySelectorAll(".nav-link").forEach(v=>v.classList.toggle("active",v.dataset.view===name));
  const titles={overview:"System overview",hosts:"Monitored hosts",disk:"Disk monitoring",events:"Security events",processes:"Running processes",network:"Network ports",antivirus:"Endpoint protection",services:"Windows services"};
  $("page-title").textContent=titles[name]||"System overview";
  if(name==="processes")renderProcesses(); if(name==="network")renderNetwork(); if(name==="services")renderServices(); if(name==="disk"){renderDiskMonitoring();loadDiskHistory();}
}
async function refresh() {
  try {
    const [summaryData,eventData]=await Promise.all([getJson("/api/v1/summary"),getJson("/api/v1/events?limit=100")]);
    await loadHostPage();
    events=Array.isArray(eventData)?eventData:[];
    renderOverview(summaryData||{});
    renderHosts(); renderEvents(); fillHostSelects(); renderProcesses(); renderNetwork(); renderAntivirus(); renderServices(); renderDiskMonitoring();
    const diskSelection=currentDiskSelection(), diskKey=diskSelection.hostId+"|"+diskSelection.mount;
    if(document.getElementById("view-disk").classList.contains("active") || diskKey!==lastDiskHistoryKey)loadDiskHistory();
    $("last-updated").textContent=new Date().toLocaleTimeString();
    setConnection(true,"API connected");
  } catch(error) {
    setConnection(false,"API unavailable");
    console.error("SentinelX dashboard refresh failed:",error);
  }
}
document.querySelectorAll("[data-view]").forEach(link=>link.addEventListener("click",e=>{e.preventDefault();const name=link.dataset.view;switchView(name);window.history.replaceState(null,"","#"+name);}));
$("refresh-btn").addEventListener("click",refresh);
$("host-prev").addEventListener("click",()=>{hostOffset=Math.max(0,hostOffset-HOST_PAGE_SIZE);refresh();});
$("host-next").addEventListener("click",()=>{hostOffset=Math.min(Math.max(0,hostTotal-HOST_PAGE_SIZE),hostOffset+HOST_PAGE_SIZE);refresh();});
$("host-search").addEventListener("input",()=>{hostSearch=$("host-search").value.trim();hostOffset=0;refresh();});
$("host-prev").addEventListener("click",()=>{hostOffset=Math.max(0,hostOffset-HOST_PAGE_SIZE);refresh();});
$("host-next").addEventListener("click",()=>{hostOffset=Math.min(Math.max(0,hostTotal-HOST_PAGE_SIZE),hostOffset+HOST_PAGE_SIZE);refresh();});
$("host-search").addEventListener("input",()=>{hostSearch=$("host-search").value.trim();hostOffset=0;refresh();});
$("event-search").addEventListener("input",renderEvents);
$("severity-filter").addEventListener("change",renderEvents);
$("process-host").addEventListener("change",renderProcesses);
$("network-host").addEventListener("change",renderNetwork);
$("service-host").addEventListener("change",renderServices);
$("service-search").addEventListener("input",renderServices);
$("disk-host").addEventListener("change",()=>{renderDiskMonitoring();loadDiskHistory();});
$("disk-mount").addEventListener("change",()=>{renderDiskMonitoring();loadDiskHistory();});
$("disk-search").addEventListener("input",renderDiskMonitoring);
$("disk-sort").addEventListener("change",renderDiskMonitoring);
$("disk-table").addEventListener("click",event=>{const row=event.target.closest("[data-mount]");if(!row)return;$("disk-mount").value=row.dataset.mount;renderDiskMonitoring();loadDiskHistory();});
$("disk-table").addEventListener("keydown",event=>{if(event.key!=="Enter"&&event.key!==" ")return;const row=event.target.closest("[data-mount]");if(!row)return;event.preventDefault();$("disk-mount").value=row.dataset.mount;renderDiskMonitoring();loadDiskHistory();});
window.addEventListener("resize",()=>{drawChart();drawDiskHistoryChart();});
refresh();
setInterval(refresh,REFRESH_MS);