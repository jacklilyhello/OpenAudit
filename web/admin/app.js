const $=id=>document.getElementById(id);
async function json(url, opts){ const r=await fetch(url,opts); return r.json(); }
function renderStats(s){ $('stats').innerHTML=['rules','enabled_rules','disabled_rules','keywords','regex','domains','pinyin_variants','homophone_variants'].map(k=>`<div><b>${k}</b><span>${s[k]??0}</span></div>`).join('')+['categories','risk_levels','actions','sources'].map(k=>`<div class="wide"><b>${k}</b><pre>${JSON.stringify(s[k]||{},null,2)}</pre></div>`).join(''); }
$('health').onclick=async()=>{$('message').textContent=JSON.stringify(await json('/health'));};
$('statsBtn').onclick=async()=>renderStats(await json('/rules/stats'));
$('reload').onclick=async()=>{const r=await json('/rules/reload',{method:'POST'}); $('message').textContent=r.ok?`✅ ${r.message}`:`❌ ${r.message}: ${r.error}`; renderStats(r.stats);};
$('audit').onclick=async()=>{const r=await json('/audit/text',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:$('text').value,options:{normalize:true}})}); $('normalized').textContent=r.normalized_text||''; $('hits').innerHTML=(r.hits||[]).map(h=>`<tr><td>${h.type}</td><td>${h.rule_id}</td><td>${h.category}</td><td>${h.risk_level}</td><td>${h.action}</td><td>${h.match}</td><td>${h.canonical||''}</td><td>${h.score}</td></tr>`).join(''); $('raw').textContent=JSON.stringify(r,null,2);};
$('statsBtn').click();
