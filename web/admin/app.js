const $ = (id) => document.getElementById(id);
async function show(target, promise) { try { const res = await promise; $(target).textContent = JSON.stringify(await res.json(), null, 2); } catch (err) { $(target).textContent = err.message; } }
$('health').onclick = () => show('status', fetch('/health'));
$('stats').onclick = () => show('status', fetch('/rules/stats'));
$('reload').onclick = () => show('status', fetch('/rules/reload', { method: 'POST' }));
$('audit').onclick = () => show('result', fetch('/audit/text', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: $('text').value, options: { normalize: true } }) }));
$('stats').click();
