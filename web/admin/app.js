const $ = id => document.getElementById(id);
const state = { reviewCases: [], selectedCase: null, policy: null };

$('apiKey').value = localStorage.getItem('openaudit_api_key') || '';

document.querySelectorAll('.nav').forEach(btn => {
  btn.addEventListener('click', () => showView(btn.dataset.view));
});

function showView(id) {
  document.querySelectorAll('.nav').forEach(b => b.classList.toggle('active', b.dataset.view === id));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === id));
  $('pageTitle').textContent = document.querySelector(`.nav[data-view="${id}"]`).textContent;
}

function saveKey() {
  localStorage.setItem('openaudit_api_key', $('apiKey').value);
}

function headers() {
  const h = {'Content-Type': 'application/json'};
  const k = $('apiKey').value;
  if (k) h['X-API-Key'] = k;
  return h;
}

async function api(url, opt = {}) {
  opt.headers = {...headers(), ...(opt.headers || {})};
  const res = await fetch(url, opt);
  const text = await res.text();
  if (!res.ok) {
    $('error').textContent = text;
    throw new Error(text);
  }
  $('error').textContent = '';
  return text ? JSON.parse(text) : {};
}

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'onclick') node.addEventListener('click', v);
    else node.setAttribute(k, v);
  }
  for (const kid of kids) node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return node;
}

function badge(value, kind) {
  return el('span', {class: `badge ${kind}-${value || 'low'}`}, value || '-');
}

function fmtTime(v) {
  if (!v) return '-';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? v : d.toLocaleString();
}

function metric(label, value) {
  return el('div', {class: 'metric'}, el('span', {}, label), el('strong', {}, value ?? 0));
}

function renderMetrics(target, stats) {
  const box = $(target);
  box.replaceChildren(
    metric('Pending cases', stats.pending),
    metric('Critical pending', stats.critical_pending),
    metric('Temporary blocked', stats.temporary_blocked),
    metric('Temporary allowed', stats.temporary_allowed),
    metric('Reviewed today', stats.reviewed_today)
  );
}

async function loadOverview() {
  try {
    const stats = await api('/review/stats');
    renderMetrics('metricGrid', stats);
    renderMetrics('reviewMetricGrid', stats);
  } catch (_) {
    $('metricGrid').replaceChildren(metric('Review queue', 'unavailable'));
  }
}

function renderAuditResult(res) {
  const rows = (res.hits || []).map(h => `${h.rule_id} ${h.type}${h.variant_type ? '/' + h.variant_type : ''} score=${h.score} risk=${h.risk_level} action=${h.action} match=${h.match}${h.explanation ? '\n  ' + h.explanation : ''}`).join('\n');
  $('auditResult').textContent = `decision=${res.action} score=${res.risk_score} matched=${res.matched}
review=${res.review_status || '-'} case=${res.review_case_id || '-'} temporary=${res.temporary_action || '-'}
${rows}

${JSON.stringify(res, null, 2)}`;
  loadOverview();
}

async function auditText() {
  renderAuditResult(await api('/audit/text', {method: 'POST', body: JSON.stringify({text: $('text').value, options: {max_hits: 20}})}));
}

async function loadReviewCases() {
  const q = new URLSearchParams();
  if ($('reviewStatus').value) q.set('status', $('reviewStatus').value);
  if ($('reviewPriority').value) q.set('priority', $('reviewPriority').value);
  if ($('reviewAction').value) q.set('temporary_action', $('reviewAction').value);
  if ($('reviewCategory').value) q.set('category', $('reviewCategory').value);
  if ($('reviewMinScore').value) q.set('min_score', $('reviewMinScore').value);
  q.set('sort', 'created_at');
  const data = await api('/review/cases?' + q.toString());
  state.reviewCases = data.items || [];
  const body = $('reviewRows');
  body.replaceChildren();
  for (const item of state.reviewCases) {
    body.append(el('tr', {},
      el('td', {}, badge(item.priority, 'priority')),
      el('td', {}, badge(item.status, 'status')),
      el('td', {}, item.ai_score ? item.ai_score.toFixed(2) : '-'),
      el('td', {}, item.variant_score ? item.variant_score.toFixed(2) : '-'),
      el('td', {}, item.deterministic_decision || '-'),
      el('td', {}, item.temporary_action || '-'),
      el('td', {}, item.category || '-'),
      el('td', {}, item.source || '-'),
      el('td', {}, fmtTime(item.created_at)),
      el('td', {}, el('button', {onclick: () => showReviewCase(item.case_id)}, 'Open'))
    ));
  }
  loadOverview();
}

async function showReviewCase(id) {
  const data = await api('/review/cases/' + encodeURIComponent(id));
  const item = data.case;
  state.selectedCase = item;
  const actions = el('div', {class: 'toolbar'},
    el('button', {onclick: () => decideCase('approve')}, 'Approve'),
    el('button', {onclick: () => decideCase('reject')}, 'Reject'),
    el('button', {onclick: () => decideCase('ignore')}, 'Ignore'),
    el('button', {onclick: () => decideCase('escalate')}, 'Escalate'),
    el('button', {onclick: () => decideCase('reopen')}, 'Reopen')
  );
  const note = el('textarea', {id: 'caseNote', placeholder: 'Internal operator note'});
  $('drawerContent').replaceChildren(
    el('h2', {}, item.case_id),
    el('p', {class: 'muted'}, `${item.source || '-'} · ${fmtTime(item.created_at)}`),
    el('div', {class: 'toolbar'}, badge(item.priority, 'priority'), badge(item.status, 'status'), badge(item.ai_risk_level, 'risk'), badge(item.variant_risk_level, 'risk')),
    el('p', {}, `Temporary action: ${item.temporary_action || '-'}`),
    el('p', {}, `Deterministic decision: ${item.deterministic_decision || '-'}`),
    el('h3', {}, 'Content excerpt'),
    el('pre', {}, item.content_excerpt || ''),
    note,
    el('button', {onclick: addCaseNote}, 'Add Note'),
    actions,
    details('Matched rules', item.matched_rules_json),
    details('AI review', item.ai_review_json),
    details('Variant review', item.variant_review_json),
    details('Decision metadata', item.decision_json),
    details('Events', JSON.stringify(data.events || [], null, 2))
  );
  $('drawer').classList.add('open');
}

function details(title, body) {
  return el('details', {class: 'evidence'}, el('summary', {}, title), el('pre', {}, prettyJSON(body)));
}

function prettyJSON(body) {
  if (!body) return '';
  try { return JSON.stringify(JSON.parse(body), null, 2); } catch (_) { return body; }
}

function closeDrawer() {
  $('drawer').classList.remove('open');
}

async function decideCase(action) {
  if (!state.selectedCase) return;
  const note = $('caseNote') ? $('caseNote').value : '';
  await api(`/review/cases/${encodeURIComponent(state.selectedCase.case_id)}/decide`, {method: 'POST', body: JSON.stringify({action, note})});
  await loadReviewCases();
  await showReviewCase(state.selectedCase.case_id);
}

async function addCaseNote() {
  if (!state.selectedCase) return;
  await api(`/review/cases/${encodeURIComponent(state.selectedCase.case_id)}/note`, {method: 'POST', body: JSON.stringify({note: $('caseNote').value})});
  await showReviewCase(state.selectedCase.case_id);
}

async function exportReviewCases() {
  const res = await fetch('/review/export?format=csv', {headers: headers()});
  const text = await res.text();
  if (!res.ok) {
    $('error').textContent = text;
    return;
  }
  const blob = new Blob([text], {type: 'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = el('a', {href: url, download: 'openaudit-review-cases.csv'});
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function loadAIReviews() {
  const data = await api('/storage/ai_audit_logs?limit=50');
  const body = $('aiRows');
  body.replaceChildren();
  for (const item of data.items || []) {
    body.append(el('tr', {},
      el('td', {}, fmtTime(item.created_at)),
      el('td', {}, `${item.provider || '-'} / ${item.model || '-'}`),
      el('td', {}, item.status || '-'),
      el('td', {}, item.action || '-'),
      el('td', {}, item.confidence ? item.confidence.toFixed(2) : '-'),
      el('td', {}, badge(item.risk_level, 'risk')),
      el('td', {}, item.latency_ms || 0)
    ));
  }
}

async function loadConfig() {
  $('config').textContent = JSON.stringify(await api('/config'), null, 2);
}

async function loadReviewPolicy() {
  const data = await api('/review/policy');
  state.policy = data.policy;
  renderPolicyForm(state.policy);
}

function renderPolicyForm(policy) {
  const fields = [
    ['enabled', 'checkbox'], ['ai_review_enabled', 'checkbox'], ['variant_review_enabled', 'checkbox'], ['allow_ai_hard_block', 'checkbox'],
    ['ai_score_review_threshold', 'number'], ['ai_score_temporary_block_threshold', 'number'], ['ai_score_log_only_below', 'number'], ['variant_score_review_threshold', 'number'],
    ['uncertain_default_action', 'text'], ['retention_days', 'number'], ['content_excerpt_max_bytes', 'number'], ['max_export_rows', 'number']
  ];
  $('policyForm').replaceChildren(...fields.map(([name, type]) => {
    const input = el('input', {id: 'policy_' + name, type});
    if (type === 'checkbox') input.checked = !!policy[name];
    else input.value = policy[name] ?? '';
    if (type === 'number') input.step = name.includes('threshold') || name.includes('below') ? '0.01' : '1';
    return el('label', {}, name, input);
  }));
}

async function saveReviewPolicy() {
  const p = {...state.policy};
  document.querySelectorAll('#policyForm input').forEach(input => {
    const name = input.id.replace('policy_', '');
    p[name] = input.type === 'checkbox' ? input.checked : (input.type === 'number' ? Number(input.value) : input.value);
  });
  const data = await api('/review/policy', {method: 'PUT', body: JSON.stringify(p)});
  state.policy = data.policy;
  renderPolicyForm(state.policy);
}

async function loadRules() {
  const data = await api('/rules?q=' + encodeURIComponent($('ruleQ').value));
  const box = $('rulesList');
  box.replaceChildren();
  for (const r of data.items || []) {
    box.append(el('div', {class: 'item'},
      el('div', {class: 'item-main'}, `${r.id} · ${r.type} · ${r.category} · ${r.action}${r.variant && r.variant.enabled ? ' · variant' : ''}`),
      el('div', {}, el('button', {onclick: () => detail(r.id)}, 'Details'), el('button', {onclick: () => toggleRule(r.id, !r.enabled)}, 'Toggle'), el('button', {onclick: () => delRule(r.id)}, 'Delete'))
    ));
  }
}

async function detail(id) {
  $('ruleDetail').textContent = JSON.stringify(await api('/rules/' + encodeURIComponent(id)), null, 2);
}

async function createRule() {
  const id = $('newId').value;
  const kws = $('newWords').value.split(',').map(s => s.trim()).filter(Boolean);
  await api('/rules/create', {method: 'POST', body: JSON.stringify({rule: {id, type: 'keyword', category: 'custom', risk_level: 'medium', action: 'review', score: 60, enabled: true, keywords: kws}})});
  await loadRules();
}

async function toggleRule(id, enabled) {
  await api('/rules/update/' + encodeURIComponent(id), {method: 'PATCH', body: JSON.stringify({patch: {enabled}})});
  await loadRules();
}

async function delRule(id) {
  await api('/rules/delete/' + encodeURIComponent(id), {method: 'DELETE'});
  await loadRules();
}

async function loadStats() {
  $('stats').textContent = JSON.stringify(await api('/logs/stats'), null, 2);
}

async function loadLogs() {
  $('logs').textContent = JSON.stringify(await api('/logs/recent?limit=20'), null, 2);
}

async function loadHistory() {
  const q = new URLSearchParams();
  for (const [id, key] of [['histRule', 'rule_id'], ['histAction', 'action'], ['histActor', 'actor'], ['histSource', 'source'], ['histBatch', 'import_batch_id']]) {
    const value = $(id).value;
    if (value) q.set(key, value);
  }
  const data = await api('/rules/history?' + q.toString());
  const box = $('history');
  box.replaceChildren();
  for (const x of data.items || []) {
    box.append(el('div', {class: 'item'},
      el('div', {class: 'item-main'}, `${x.change_id} · ${x.timestamp} · ${x.action} · ${x.rule_id || ''} · ${x.actor || ''}`),
      el('div', {}, el('button', {onclick: () => showChange(x.change_id)}, 'Open'), el('button', {onclick: () => showDiff(x.rule_id || '')}, 'Diff'), el('button', {onclick: () => rollbackChange(x.rule_id || '', x.change_id)}, 'Rollback'))
    ));
  }
}

async function showChange(id) {
  $('historyDetail').textContent = JSON.stringify(await api('/rules/history/' + encodeURIComponent(id)), null, 2);
}

async function showDiff(id) {
  if (!id) {
    $('historyDiff').textContent = 'No rule id for this change';
    return;
  }
  $('historyDiff').textContent = JSON.stringify(await api('/rules/' + encodeURIComponent(id) + '/diff'), null, 2);
}

async function rollbackChange(rule, change) {
  if (!rule || !confirm('Rollback ' + rule + ' to before ' + change + '?')) return;
  $('historyDetail').textContent = JSON.stringify(await api('/rules/rollback/' + encodeURIComponent(rule), {method: 'POST', body: JSON.stringify({change_id: change, note: 'admin rollback'})}), null, 2);
  await loadHistory();
  await loadRules();
}

async function loadBatches() {
  const data = await api('/imports/batches');
  const box = $('batches');
  box.replaceChildren();
  for (const x of data.items || []) {
    box.append(el('div', {class: 'item'},
      el('div', {class: 'item-main'}, `${x.batch_id} · ${x.timestamp} · ${x.source} · ${x.status}`),
      el('div', {}, el('button', {onclick: () => showBatch(x.batch_id)}, 'Open'), el('button', {onclick: () => rollbackBatch(x.batch_id)}, 'Rollback'))
    ));
  }
}

async function showBatch(id) {
  $('batchDetail').textContent = JSON.stringify(await api('/imports/batches/' + encodeURIComponent(id)), null, 2);
}

function importPayload() {
  return {input_path: $('impInput').value, output_path: $('impOutput').value, source: $('impSource').value || 'sensitive-lexicon', type: $('impType').value, category: $('impCategory').value, risk_level: $('impRisk').value || 'medium', action: $('impAction').value || 'review', strict: $('impStrict').checked, reload_after_import: $('impReload').checked, record_history: true};
}

async function importPreview() {
  $('importResult').textContent = JSON.stringify(await api('/imports/preview', {method: 'POST', body: JSON.stringify(importPayload())}), null, 2);
}

async function runImport() {
  $('importResult').textContent = JSON.stringify(await api('/imports/run', {method: 'POST', body: JSON.stringify(importPayload())}), null, 2);
}

async function createDraft() {
  const id = $('draftId').value;
  const kws = $('draftWords').value.split(',').map(s => s.trim()).filter(Boolean);
  $('releaseResult').textContent = JSON.stringify(await api('/rules/drafts', {method: 'POST', body: JSON.stringify({rule: {id, type: 'keyword', category: 'custom', risk_level: 'medium', action: 'review', score: 60, keywords: kws}})}), null, 2);
  await loadDrafts();
}

async function loadDrafts() {
  const data = await api('/rules/drafts');
  renderSimpleRules('drafts', data.items || [], r => el('button', {onclick: () => stageDraft(r.id)}, 'Stage'));
}

async function stageDraft(id) {
  $('releaseResult').textContent = JSON.stringify(await api('/rules/drafts/' + encodeURIComponent(id) + '/stage', {method: 'POST'}), null, 2);
  await loadDrafts();
  await loadStaged();
}

async function loadStaged() {
  const data = await api('/rules/staged');
  renderSimpleRules('staged', data.items || []);
}

function renderSimpleRules(target, items, actionFactory) {
  const box = $(target);
  box.replaceChildren();
  for (const r of items) {
    box.append(el('div', {class: 'item'}, el('div', {class: 'item-main'}, `${r.id} · ${r.type} · ${r.category}`), actionFactory ? actionFactory(r) : el('span', {}, '')));
  }
}

async function publishStaged() {
  $('releaseResult').textContent = JSON.stringify(await api('/rules/publish', {method: 'POST', body: JSON.stringify({sample_text: $('simulateText').value})}), null, 2);
  await loadRules();
  await loadStaged();
  await loadReleases();
}

async function loadReleases() {
  const data = await api('/rules/releases');
  const box = $('releaseList');
  box.replaceChildren();
  for (const r of data.items || []) {
    box.append(el('div', {class: 'item'}, el('div', {class: 'item-main'}, `${r.version} · ${r.status} · rules=${r.rule_count}`), el('div', {}, el('button', {onclick: () => showRelease(r.version)}, 'Open'), el('button', {onclick: () => rollbackRelease(r.version)}, 'Rollback'))));
  }
}

async function showRelease(version) {
  $('releaseResult').textContent = JSON.stringify(await api('/rules/releases/' + encodeURIComponent(version)), null, 2);
}

async function rollbackRelease(version) {
  if (!confirm('Rollback ruleset to ' + version + '?')) return;
  $('releaseResult').textContent = JSON.stringify(await api('/rules/releases/' + encodeURIComponent(version) + '/rollback', {method: 'POST'}), null, 2);
  await loadRules();
  await loadReleases();
}

async function detectConflicts() {
  $('releaseResult').textContent = JSON.stringify(await api('/rules/conflicts', {method: 'POST'}), null, 2);
}

async function simulateRules() {
  $('releaseResult').textContent = JSON.stringify(await api('/rules/simulate', {method: 'POST', body: JSON.stringify({text: $('simulateText').value, scope: $('simulateScope').value, max_hits: 20})}), null, 2);
}

async function bulkDisableCustom() {
  await api('/rules/bulk/disable', {method: 'POST', body: JSON.stringify({category: 'custom', state: 'published'})});
  await loadRules();
}

async function bulkEnableCustom() {
  await api('/rules/bulk/enable', {method: 'POST', body: JSON.stringify({category: 'custom', state: 'published'})});
  await loadRules();
}

async function rollbackBatch(id) {
  if (!confirm('Rollback import batch ' + id + '?')) return;
  $('batchDetail').textContent = JSON.stringify(await api('/imports/batches/' + encodeURIComponent(id) + '/rollback', {method: 'POST'}), null, 2);
  await loadBatches();
  await loadRules();
}

loadOverview();
loadReviewCases().catch(() => {});
loadRules().catch(() => {});
loadReviewPolicy().catch(() => {});
