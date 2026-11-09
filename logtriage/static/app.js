'use strict';
const $ = id => document.getElementById(id);
let csrf = '', current = null, settingsDirty = false, settingsLoaded = false, busy = false, profileChoice = null;
const date = value => value ? new Date(value).toLocaleString('fr-CH', {dateStyle:'short',timeStyle:'short'}) : '—';
function notice(text, error = false) { $('notice').textContent = text; $('notice').hidden = !text; $('notice').classList.toggle('error', error); }
function view() { const name = ['bilan','controles','rapport','reglages'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'bilan'; document.querySelectorAll('.view').forEach(section => section.hidden = section.id !== 'view-' + name); document.querySelectorAll('[data-view]').forEach(a => { if(a.dataset.view === name) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current'); }); }
async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials:'same-origin', headers:body === undefined ? {} : {'Content-Type':'application/json','X-CSRF-Token':csrf},body:body === undefined ? undefined : JSON.stringify(body)});
  const result = await response.json();
  if (response.status === 401) { $('application').hidden = true; $('login-view').hidden = false; settingsLoaded = false; }
  if (!response.ok) throw new Error(result.error || 'Opération indisponible. Réessaie.');
  return result;
}
function options(select, rows, selected, placeholder) { const fingerprint=JSON.stringify(rows); if(select.dataset.rows!==fingerprint) {select.replaceChildren(); if(placeholder) select.add(new Option(placeholder,'')); rows.forEach(row => select.add(new Option(row.label,row.id)));select.dataset.rows=fingerprint;} if(select!==document.activeElement)select.value = selected || ''; }
function settings(state) {
  if (!settingsDirty || !settingsLoaded) {
    for(const [key,value] of Object.entries(state.settings)) { const input=$(key); if(input) { if(input.type === 'checkbox') input.checked=value; else input.value=value; } }
    settingsLoaded = true;
  }
  const selectedModel = settingsDirty ? $('ai_model').value : state.settings.ai_model;
  options($('ai_model'), state.models.map(m=>({id:m.slug,label:m.display_name})), selectedModel, 'Sélectionne un modèle');
  options($('account-picker'),state.chatgpt.profiles.map(p=>({id:p.id,label:p.label+(p.needs_login?' — à reconnecter':'')})), profileChoice===null?state.chatgpt.active:profileChoice, 'Ajouter un compte');
  $('disconnect-chatgpt').disabled = !state.chatgpt.connected;
  $('load-models').disabled = !state.chatgpt.connected || busy;
  $('chatgpt-status').textContent = state.chatgpt.connected ? 'Compte connecté. Le serveur peut utiliser ton abonnement ChatGPT, même si ton Mac est éteint.' : 'Aucun compte ChatGPT actif. Le bilan classique reste disponible.';
  $('mailbox-description').textContent = [state.mailbox.user, state.mailbox.host, state.mailbox.folder].filter(Boolean).join(' · ') || 'La connexion IMAP se configure sur le serveur.';
  const selected = state.chatgpt.active;
  if(state.chatgpt.connected && selected && !localStorage.getItem('logtriage-welcome-'+selected)) { $('plan-welcome').showModal(); localStorage.setItem('logtriage-welcome-'+selected,'1'); }
}
function showReport(container, body) {
  if (container.dataset.rendered === body) return;
  container.dataset.rendered = body;
  const fragment = document.createDocumentFragment();
  const headings = ['À EXAMINER EN PRIORITÉ', 'PROBLÈMES TOUJOURS OUVERTS', 'RÉTABLIS AUJOURD’HUI'];
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const heading = headings.includes(line);
    const item = document.createElement(heading ? 'h3' : 'p');
    item.textContent = heading ? line[0] + line.slice(1).toLocaleLowerCase('fr') : line.replace(/^- /, '');
    if (line.startsWith('- ')) item.className = 'report-item';
    else if (raw.startsWith('  ')) item.className = 'report-detail';
    fragment.append(item);
  }
  container.replaceChildren(fragment);
}
function checkedIncidents() {
  return Array.from($('incident-list').querySelectorAll('input:checked'), input => input.value);
}
function incidentSelection() {
  const count = checkedIncidents().length;
  const button = $('resolve-incident');
  button.textContent = count ? 'Marquer comme résolu' + (count > 1 ? 's' : '') + ' (' + count + ')' : 'Valider la sélection';
  button.disabled = !count || busy || current?.report?.job?.state === 'running';
}
function analysisStatus(analysis) {
  if (!analysis) return 'L’analyse IA des incidents est désactivée.';
  const statuses = {pending:'Analyse IA en attente.', error:'Analyse IA différée. Nouvel essai automatique.',
    configure:'Pour analyser cet incident, connecte ChatGPT et choisis un modèle dans les réglages.'};
  const reasons = {usage_limit:'Limite ChatGPT atteinte. L’analyse reprendra après un délai.',
    invalid_analysis:'La réponse IA ou sa citation n’a pas pu être validée. Un nouvel essai est prévu.',
    login_required:'Reconnecte le compte ChatGPT dans les réglages.', model_unavailable:'Actualise les modèles et choisis un modèle disponible.'};
  return reasons[analysis.reason] || statuses[analysis.state] || 'Analyse indisponible.';
}
function updateIncidentAnalysis(row) {
  const box = $('analysis-body');
  const signature = JSON.stringify([row.id, row.analysis]);
  if (box.dataset.signature === signature) return;
  box.dataset.signature = signature;
  const analysis = row.analysis;
  if (analysis?.state === 'ready') {
    box.replaceChildren(element('p','',analysis.constat), element('blockquote','',analysis.preuve),
      element('p','','Vérification proposée : '+analysis.verification));
  } else {
    box.textContent = analysisStatus(analysis);
  }
}
function inspectButton(title, open) {
  const inspect = button('', open);
  inspect.className = 'inspect';
  inspect.title = title;
  inspect.setAttribute('aria-label',title);
  return inspect;
}
function openIncident(row) {
  $('detail-title').textContent = row.missing ? 'Rapport manquant' : 'Détail de l’incident';
  $('detail-context').textContent = row.summary+' · '+clientLabel(row.client)+' · '+serviceLabel(row)+' · '+date(row.date);
  $('detail-signals').hidden = true;
  $('incident-analysis').hidden = false;
  $('incident-analysis').dataset.signal = row.id;
  updateIncidentAnalysis(row);
  $('check-detail').showModal();
  showMailDetail(row.detail_id);
}
function renderIncidents(rows) {
  const list = $('incident-list');
  const fingerprint = JSON.stringify(rows);
  if (list.dataset.rows !== fingerprint) {
    const selected = new Set(checkedIncidents());
    const expanded = new Set(Array.from(list.querySelectorAll('details[open]'), node => node.dataset.signal));
    const focused = list.contains(document.activeElement) ? document.activeElement.value : null;
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      const item = document.createElement('li');
      const label = document.createElement('label');
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.value = row.id;
      checkbox.checked = selected.has(row.id);
      const text = document.createElement('span');
      text.textContent = row.summary;
      text.append(element('small','issue-client','Client : '+clientLabel(row.client)+' · Service : '+serviceLabel(row)+' · Type : '+typeLabel(row)));
      const when = element('time','issue-date',date(row.date));
      when.dateTime = row.date;
      text.className = 'issue-name';
      text.prepend(element('span','sr-only',row.severity === 'open' ? 'Échec — ' : 'Avertissement — '));
      label.append(checkbox, when, text);
      item.dataset.kind = row.severity === "open" ? "bad" : "warn";
      const line = element('div','issue-line');
      line.append(label, inspectButton('Voir le détail de l’incident · '+clientLabel(row.client)+' · '+row.summary,
        () => openIncident(row)));
      item.append(line);
      if (row.analysis?.state === 'ready') {
        const note = element('details','incident-note');
        note.dataset.signal = row.id;
        note.open = expanded.has(row.id);
        note.append(element('summary','','Analyse IA · '+row.analysis.constat),
          element('p','','Élément relevé : « '+row.analysis.preuve+' »'),
          element('p','','Vérification proposée : '+row.analysis.verification));
        item.append(note);
      } else if (row.analysis) {
        item.append(element('p','incident-note muted', analysisStatus(row.analysis)));
      }
      fragment.append(item);
    }
    list.replaceChildren(fragment);
    if (focused) Array.from(list.querySelectorAll('input')).find(input => input.value === focused)?.focus({preventScroll:true});
    list.dataset.rows = fingerprint;
  }
  $('issues-head').hidden = rows.length === 0;
  $('incident-count').textContent = '(' + rows.length + ')';
  $('incident-empty').hidden = rows.length !== 0;
  $('incident-hint').hidden = $('resolve-incident').hidden = list.hidden = rows.length === 0;
  incidentSelection();
}
function render(state) {
  current=state; csrf=state.csrf;
  $('login-view').hidden=true; $('application').hidden=false;
  $('version').textContent='Logtriage '+state.version;
  const collection=state.status?.collection, status=state.status?.state;
  const stale=state.status && Date.now()-Date.parse(state.status.last_cycle_at)>Math.max(900,state.status.poll_seconds*3)*1000;
  $('collection-status').textContent=!state.status ? 'La première collecte n’est pas encore disponible.' : stale ? 'La dernière collecte est ancienne. Vérifie le service avant de te fier au bilan.' : status !== 'ok' ? 'Collecte à vérifier : le bilan reflète les données disponibles.' : collection?.pending ? `Collecte en cours : ${collection.pending} emails restent à analyser.` : 'Collecte à jour · boîte consultée en lecture seule';
  $('last-collection').textContent=date(state.status?.last_cycle_at);
  showReport($('latest-digest'), state.latest_digest || 'Le bilan apparaîtra après la première collecte.');
  renderRegistry(state.clients || []);
  renderIncidentView(state.incidents || []);
  if ($('check-detail').open && !$('incident-analysis').hidden) {
    const incident = state.incidents.find(row => row.id === $('incident-analysis').dataset.signal);
    if (incident) updateIncidentAnalysis(incident);
  }
  renderClientView(state);
  settings(state);
  renderMonitoring(state);
  const preview=state.report.preview, job=state.report.job, running=job.state==='running';
  $('prepare').disabled=running || busy; $('prepare').textContent=running&&job.kind==='preview'?'Préparation en cours…':'Préparer le rapport'; $('prepare').setAttribute('aria-busy',String(running&&job.kind==='preview'));
  $('recipient-summary').textContent=state.settings.recipient?'Destinataire : '+state.settings.recipient:'Renseigne le destinataire dans les réglages.';
  $('ai-plan-status').textContent=state.chatgpt.connected?'Utilise ton abonnement ChatGPT.':'Connecte ChatGPT dans les réglages pour ajouter une analyse.';
  $('mail-headers').hidden=!preview; $('report-preview').classList.toggle('empty',!preview);
  $('preview-date').textContent=preview?'Préparé le '+date(preview.created_at):'';
  showReport($('report-preview'), preview?.body || 'Choisis le type de bilan, puis prépare l’aperçu.');
  $('preview-to').textContent=preview?.recipient||''; $('preview-subject').textContent=preview?.subject||'';
  $('ai-warning').hidden=!preview?.ai?.message; $('ai-warning').textContent=preview?.ai?.message||'';
  const policyChanged = preview?.policy_id && preview.policy_id !== state.summary?.policy_id;
  const stalePreview = preview && (policyChanged || (preview.resolution_count || 0) !== (state.summary?.resolution_count || 0));
  $('send').disabled=!preview || stalePreview || running || preview.delivery!=='not_sent' || busy;
  $('send').textContent=running&&job.kind==='send'?'Envoi en cours…':'Envoyer cet aperçu';
  $('delivery-status').textContent=preview?.delivery_message || (preview?.ai?.state==='completed'?'Analyse ChatGPT ajoutée. Aucun envoi effectué.':'Aucun envoi effectué depuis cet aperçu.');
  if (stalePreview && preview.delivery === 'not_sent') $('delivery-status').textContent = policyChanged ? 'Les règles ou les calendriers ont changé. Prépare un nouvel aperçu.' : 'Un incident a été validé. Prépare un nouvel aperçu pour l’envoyer.';
  $('last-send').textContent=state.report.last_send?'Dernière acceptation SMTP : '+date(state.report.last_send.accepted_at)+' pour '+state.report.last_send.recipient:'';
  if(job.state==='error') notice(job.message,true);
  view();
}
async function refresh(quiet = false) { try {render(await api('/api/state'));} catch(error) {if($('application').hidden) {$('login-view').hidden=false;if(error instanceof TypeError)$('login-error').textContent='Le serveur est injoignable. Réessaie la connexion.';} else if(!quiet) notice(error.message,true);} }
async function action(button, fn) { if(busy) return; busy=true; button.disabled=true; button.setAttribute('aria-busy','true'); notice(''); try{await fn();}catch(error){notice(error.message,true);}finally{busy=false;button.disabled=false;button.removeAttribute('aria-busy');await refresh(true);} }
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$('login-error').textContent='';try{const result=await api('/api/login',{username:$('username').value,password:$('password').value});csrf=result.csrf;$('password').value='';await refresh();}catch(error){$('login-error').textContent=error.message;}finally{button.disabled=false;}});
$('logout').addEventListener('click',()=>action($('logout'),async()=>{await api('/api/logout',{});current=null;settingsDirty=false;settingsLoaded=false;$('application').hidden=true;$('login-view').hidden=false;}));
$('incident-list').addEventListener('change', () => {
  $('resolution-status').textContent = '';
  incidentSelection();
});
$('manage-incidents').addEventListener('click', () => {
  requestAnimationFrame(() => $('incident-heading').focus());
});
$('resolve-incident').addEventListener('click', () => {
  const ids = checkedIncidents();
  if (!ids.length) return;
  action($('resolve-incident'), async () => {
    await api('/api/resolve', {ids});
    $('resolution-status').textContent = ids.length === 1 ? '1 incident validé comme résolu.' : ids.length + ' incidents validés comme résolus.';
  });
});
$('refresh').addEventListener('click',()=>refresh());
$('settings-form').addEventListener('input',()=>{settingsDirty=true;$('settings-status').textContent='Modifications non enregistrées.';});
$('settings-form').addEventListener('submit',event=>{event.preventDefault();action($('save-settings'),async()=>{const body={};for(const [key,value] of Object.entries(current.settings)){const input=$(key);body[key]=input.type==='checkbox'?input.checked:typeof value==='number'?Number(input.value):input.value;}await api('/api/settings',body);settingsDirty=false;$('settings-status').textContent='Réglages enregistrés.';});});
$('prepare').addEventListener('click',()=>action($('prepare'),async()=>{await api('/api/preview',{use_ai:$('use-ai').checked});}));
$('send').addEventListener('click',()=>action($('send'),async()=>{if(current?.report?.preview)await api('/api/send',{id:current.report.preview.id});}));
$('connect-chatgpt').addEventListener('click',()=>action($('connect-chatgpt'),async()=>{const profile=$('account-picker').value||null;const data=await api('/api/chatgpt/connect',{profile});const binary=Uint8Array.from(atob(data.archive),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([binary],{type:'application/zip'}));const link=document.createElement('a');link.href=url;link.download='logtriage-chatgpt.zip';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('connection-help').hidden=false;}));
$('disconnect-chatgpt').addEventListener('click',()=>action($('disconnect-chatgpt'),async()=>{const result=await api('/api/chatgpt/disconnect',{});notice(result.message);}));
$('account-picker').addEventListener('change',()=>{profileChoice=$('account-picker').value;if(profileChoice)action($('account-picker'),async()=>{await api('/api/chatgpt/select',{profile:profileChoice});});});
$('load-models').addEventListener('click',()=>action($('load-models'),async()=>{await api('/api/models',{});notice('Modèles disponibles actualisés. Choisis un modèle puis enregistre les réglages.');}));
const weekdays = ['Lun','Mar','Mer','Jeu','Ven','Sam','Dim'];
const outcomeNames = {failure:'Échec', warning:'Avertissement', completed:'Fin annoncée', success:'Réussite confirmée'};
let ruleToken = null;
for (const [index, name] of weekdays.entries()) {
  const label = document.createElement('label');
  label.className = 'checkbox';
  const input = document.createElement('input');
  input.type = 'checkbox';
  input.value = String(index);
  input.checked = true;
  label.append(input, name);
  $('schedule-days').append(label);
}
function clearTest() {
  ruleToken = null;
  $('rule-result').replaceChildren();
  $('activate-rule').hidden = true;
}
function renderPolicyList(id, rows, makeRow) {
  const list = $(id);
  const key = JSON.stringify(rows);
  if (list.dataset.rows === key) return;
  list.replaceChildren(...rows.map(makeRow));
  list.dataset.rows = key;
}
function button(text, callback) {
  const el = document.createElement('button');
  el.type = 'button';
  el.textContent = text;
  el.addEventListener('click', () => callback(el));
  return el;
}
const checkLabels = {good:'Sans incident', warn:'Avertissements', bad:'Échecs', other:'À confirmer'};
const executionLabels = {success:'Réussite', failure:'Échec', warning:'Avertissement', completed:'Fin annoncée', unknown:'À confirmer'};
const dailyStates = {
  success:['good','Sans incident'], failure:['bad','Échec ouvert'], warning:['warn','Avertissement ouvert'],
  unknown:['other','Résultat à confirmer'], none:['no-signal','Aucun signal']
};
function checkKind(row) {
  if (row.state === 'open') return 'bad';
  if (row.state === 'warning') return 'warn';
  if (row.state === 'ok' || row.state === 'resolved') return 'good';
  return 'other';
}
function element(tag, name, text) {
  const node = document.createElement(tag);
  if (name) node.className = name;
  if (text !== undefined) node.textContent = text;
  return node;
}
const clientLabel = domain => domain || 'Domaine indéterminé';
const serviceLabel = row => row.service || 'Autres services';
let selectedService = '*';
function matchesScope(row) {
  const client = $('client-filter').value, type = $('type-filter').value;
  return (client === '*' || (row.client || '') === client) &&
    (selectedService === '*' || serviceLabel(row) === selectedService) &&
    (type === '*' || typeLabel(row) === type);
}
function resetCheckFilters() {
  $('type-filter').value = '*';
  $('check-status').value = '';
  $('check-search').value = '';
}
function renderServices(client, items) {
  const section = $('client-services'), list = $('service-list');
  section.hidden = client === '*';
  if (section.hidden) {
    selectedService = '*';
    return;
  }
  const services = [...new Set(items.filter(row => (row.client || '') === client).map(serviceLabel))]
    .sort((a,b) => a.localeCompare(b,'fr'));
  if (!services.includes(selectedService)) selectedService = '*';
  $('services-title').textContent = 'Services de '+clientLabel(client);
  const signature = JSON.stringify(services);
  if (list.dataset.services !== signature) {
    list.replaceChildren(...['*', ...services].map(service => {
      const item = button(service === '*' ? 'Tous les services' : service, () => {
        selectedService = service;
        resetCheckFilters();
        renderClientView(current);
      });
      item.dataset.service = service;
      return item;
    }));
    if (!services.length) list.replaceChildren(element('p','muted','Aucun service identifié pour ce client.'));
    list.dataset.services = signature;
  }
  for (const item of list.querySelectorAll('button')) item.setAttribute('aria-pressed', String(item.dataset.service === selectedService));
}
const typeLabel = row => row.check_type || 'Autre contrôle';
function updateFilter(id, values, label, allLabel, registered) {
  const picker = $(id);
  const items = [...new Set(values)].sort((a,b) => label(a).localeCompare(label(b),'fr'));
  const signature = JSON.stringify([items,registered]);
  if (picker.dataset.options !== signature) {
    const selected = picker.value;
    picker.replaceChildren(new Option(allLabel,'*'));
    if (registered) {
      for (const [title, groupItems] of [['Clients enregistrés',registered], ['Domaines détectés',items.filter(v => !registered.includes(v))]]) {
        if (!groupItems.length) continue;
        const group = document.createElement('optgroup');
        group.label = title;
        group.append(...groupItems.map(v => new Option(label(v),v)));
        picker.append(group);
      }
    } else {
      picker.append(...items.map(v => new Option(label(v),v)));
    }
    picker.value = items.includes(selected) ? selected : '*';
    picker.dataset.options = signature;
  }
  return picker.value;
}
function renderIncidentView(issues) {
  const client = updateFilter('incident-client', issues.map(row => row.client || ''), clientLabel, 'Tous les clients');
  const byClient = issues.filter(row => client === '*' || (row.client || '') === client);
  const service = updateFilter('incident-service', byClient.map(serviceLabel), value => value, 'Tous les services');
  const byService = byClient.filter(row => service === '*' || serviceLabel(row) === service);
  const type = updateFilter('incident-type', byService.map(typeLabel), value => value, 'Tous les types');
  $('incident-filters').hidden = !issues.length;
  renderIncidents(byService.filter(row => type === '*' || typeLabel(row) === type));
}
$('incident-filters').addEventListener('change', event => {
  if (event.target.id === 'incident-client') $('incident-service').value = '*';
  if (event.target.id !== 'incident-type') $('incident-type').value = '*';
  renderIncidentView(current.incidents || []);
});
function renderClientView(state) {
  const counts = state.summary?.clients_today || {};
  const rows = state.checks || [], issues = state.incidents || [];
  const catalog = [...rows, ...issues, ...(state.monitoring?.tasks || [])];
  const client = updateFilter('client-filter', [...(state.clients || []), ...Object.keys(counts), ...catalog.map(r => r.client || '')],
    clientLabel, 'Tous les clients', state.clients || []);
  renderServices(client, catalog);
  const owns = row => client === '*' || (row.client || '') === client;
  const types = [...rows, ...issues].filter(r => owns(r) && (selectedService === '*' || selectedService === serviceLabel(r))).map(typeLabel);
  const type = updateFilter('type-filter', types, value => value, 'Tous les types');
  const detailFilter = selectedService !== '*' || type !== '*';
  $('message-count').textContent = client === '*' ? state.summary?.today_messages ?? '—' : counts[client]?.messages || 0;
  $('unknown-count').textContent = client === '*' ? state.summary?.today_unknown ?? '—' : counts[client]?.unknown || 0;
  for (const id of ['message-count','unknown-count']) $(id).parentElement.hidden = detailFilter;
  renderChecks(rows);
}
$('client-filter').addEventListener('change', () => {
  selectedService = '*';
  resetCheckFilters();
  renderClientView(current);
});
$('type-filter').addEventListener('change', () => renderClientView(current));
let detailRequest = 0;
function renderRegistry(names) {
  const list = $('registered-clients'), select = $('assignment-client');
  if (list.dataset.names === JSON.stringify(names)) return;
  list.dataset.names = JSON.stringify(names);
  list.replaceChildren(...names.map(name => element('li','',name)));
  $('no-clients').hidden = names.length > 0;
  const selected = select.value;
  select.replaceChildren(new Option(names.length ? 'Choisis un client' : 'Ajoute un client dans les réglages',''),
    ...names.map(name => new Option(name,name)));
  select.value = names.includes(selected) ? selected : '';
  const bulkPicker = $('bulk-client'), previous = bulkPicker.value;
  bulkPicker.replaceChildren(new Option(names.length ? 'Choisis un client' : 'Aucun client enregistré',''),
    ...names.map(name => new Option(name,name)));
  bulkPicker.value = names.includes(previous) ? previous : '';
  $('bulk-review').disabled = !names.length;
  $('bulk-create').hidden = names.length > 0;
  $('assignment-review').disabled = names.length === 0;
}
$('create-client-form').addEventListener('submit', async event => {
  event.preventDefault();
  const submit = event.submitter;
  submit.disabled = true;
  try {
    const result = await api('/api/clients/create', {name:$('new-client-name').value});
    renderRegistry(result.clients);
    $('new-client-name').value = '';
    $('client-feedback').textContent = 'Client ajouté.';
    await refresh(true);
  } catch (error) { $('client-feedback').textContent = error.message; }
  finally { submit.disabled = false; }
});
$('manage-clients').addEventListener('click', () => {
  $('check-detail').close();
  requestAnimationFrame(() => $('new-client-name').focus());
});
let assignmentId = '', assignmentToken = '';
function clearAssignment() {
  assignmentToken = '';
  $('assignment-save').hidden = true;
  $('assignment-result').textContent = '';
  $('assignment-checks').replaceChildren();
}
$('assignment-client').addEventListener('input', clearAssignment);
async function submitAssignment(save) {
  const id = assignmentId, client = $('assignment-client').value.trim(), request = detailRequest;
  const submit = save ? $('assignment-save') : $('assignment-review');
  submit.disabled = true;
  try {
    if (!save) clearAssignment();
    const result = await api('/api/assignments/'+(save ? 'save' : 'preview'), {detail_id:id, client, token:assignmentToken});
    if (save) {
      if (request === detailRequest) $('check-detail').close();
      await refresh(true);
      notice('Attribution enregistrée pour '+client+'.');
    } else if (request === detailRequest && $('assignment-client').value.trim() === client) {
      assignmentToken = result.token;
      $('assignment-result').textContent = result.criterion+' · '+result.count+' mail(s) dans l’historique.';
      $('assignment-checks').replaceChildren(...result.checks.map(key => element('li','',key.split('|').join(' · '))));
      $('assignment-save').hidden = false;
    }
  } catch (error) {
    if (request === detailRequest) { clearAssignment(); $('assignment-result').textContent = error.message; }
  } finally { submit.disabled = false; }
}
$('assignment-form').addEventListener('submit', event => { event.preventDefault(); submitAssignment(false); });
$('assignment-save').addEventListener('click', () => submitAssignment(true));
async function showMailDetail(id) {
  const request = ++detailRequest;
  clearAssignment();
  $('assign-client').hidden = true;
  $('assign-client').open = false;
  $('assignment-client').value = '';
  assignmentId = id;
  const box = $('detail-mail'), title = $('detail-mail-title');
  title.textContent = 'Résumé du mail';
  box.textContent = id ? 'Chargement du résumé…' : 'Le détail du mail est indisponible.';
  if (!id) return;
  try {
    const detail = await api('/api/check-detail/'+encodeURIComponent(id));
    if (request !== detailRequest || !$('check-detail').open) return;
    title.textContent = detail.kind === 'schedule' ? 'Suivi du rapport attendu' : 'Résumé du mail';
    box.replaceChildren(element('p','mail-summary',detail.summary || 'Résumé indisponible.'));
    if (detail.kind !== 'mail') return;
    if (detail.assignment_source) {
      $('assign-client').hidden = false;

    }
    const meta = element('p','mail-meta','Mail du '+date(detail.date)+' · '+(executionLabels[detail.execution] || 'À confirmer'));
    box.append(meta);
    if (detail.subject) box.append(element('p','mail-subject','Objet : '+detail.subject));
    if (detail.points.length) {
      const facts = element('ul','mail-points');
      facts.append(...detail.points.map(point => element('li','',point)));
      box.append(facts);
    }
  } catch (error) {
    if (request === detailRequest) box.textContent = error.message;
  }
}
const selectedChecks = new Set();
let bulkPreview = null;
function updateBulkBar() {
  const boxes = Array.from($('check-groups').querySelectorAll('input[data-check]'));
  const visible = new Set(boxes.map(box => box.value));
  const visibleSelected = [...visible].filter(id => selectedChecks.has(id)).length;
  const hidden = selectedChecks.size - visibleSelected;
  $('bulk-form').hidden = !selectedChecks.size;
  $('bulk-count').textContent = selectedChecks.size+' contrôle'+(selectedChecks.size === 1 ? ' coché' : 's cochés')+
    (hidden ? ' (dont '+hidden+' hors filtre)' : '');
  for (const box of boxes) box.checked = selectedChecks.has(box.value);
  const all = $('bulk-all');
  if (all) {
    all.disabled = !visible.size;
    all.checked = visible.size > 0 && visibleSelected === visible.size;
    all.indeterminate = visibleSelected > 0 && visibleSelected < visible.size;
  }
}
$('check-groups').addEventListener('change', event => {
  const input = event.target;
  if (!input.matches('input[type=checkbox]')) return;
  const boxes = input.id === 'bulk-all' ? $('check-groups').querySelectorAll('input[data-check]') : [input];
  for (const box of boxes) {
    if (input.checked) selectedChecks.add(box.value);
    else selectedChecks.delete(box.value);
  }
  $('bulk-status').textContent = '';
  updateBulkBar();
});
$('bulk-clear').addEventListener('click', () => { selectedChecks.clear(); updateBulkBar(); });
$('bulk-form').addEventListener('submit', async event => {
  event.preventDefault();
  const ids = [...selectedChecks].sort(), client = $('bulk-client').value;
  if (!ids.length || !client) return;
  $('bulk-review').disabled = true;
  try {
    const result = await api('/api/assignments/preview', {check_ids:ids,client});
    if (client !== $('bulk-client').value || JSON.stringify(ids) !== JSON.stringify([...selectedChecks].sort())) return;
    bulkPreview = {check_ids:ids,client,token:result.token};
    $('bulk-impact').textContent = 'Client destinataire : '+client+' · '+result.affected.length+' contrôle(s) · '+result.count+
      ' mail(s) dans l’historique. Les prochains messages correspondants seront aussi attribués à ce client.';
    $('bulk-checks').replaceChildren(...result.affected.map(row => element('li','',clientLabel(row.client)+' — '+row.key.split('|').join(' · '))));
    $('bulk-error').textContent = '';
    $('bulk-save').disabled = false;
    $('bulk-dialog').showModal();
  } catch (error) { $('bulk-status').textContent = error.message; }
  finally { $('bulk-review').disabled = !(current?.clients || []).length; }
});
$('bulk-save').addEventListener('click', async () => {
  if (!bulkPreview) return;
  const payload = bulkPreview;
  $('bulk-save').disabled = $('bulk-cancel').disabled = true;
  try {
    await api('/api/assignments/save',payload);
    selectedChecks.clear();
    $('bulk-dialog').close();
    updateBulkBar();
    await refresh(true);
    $('bulk-status').textContent = 'Attribution enregistrée pour '+payload.client+'.';
  } catch (error) { $('bulk-error').textContent = error.message+' Ferme cet aperçu et vérifie de nouveau la sélection.'; }
  finally { $('bulk-cancel').disabled = false; }
});
$('bulk-dialog').addEventListener('cancel', e => { if ($('bulk-cancel').disabled) e.preventDefault(); });
$('bulk-dialog').addEventListener('close', () => { bulkPreview = null; });
function renderChecks(rows) {
  const available = new Set(rows.map(row => row.bulk_id));
  for (const id of selectedChecks) {
    if (!available.has(id)) {
      selectedChecks.delete(id);
      $('bulk-status').textContent = 'La liste a changé. Vérifie les contrôles encore cochés.';
    }
  }
  rows = rows.filter(matchesScope);
  const counts = {good:0, warn:0, bad:0, other:0};
  rows.forEach(row => counts[checkKind(row)]++);
  const totals = $('status-totals');
  if (totals.dataset.counts !== JSON.stringify(counts)) {
    totals.dataset.counts = JSON.stringify(counts);
    totals.replaceChildren(...['good','warn','bad'].map(kind => {
      const count = button('', () => {
        $('check-status').value = kind;
        renderChecks(current.checks || []);
        $('check-status').focus();
      });
      count.className = 'total ' + kind;
      count.append(element('strong','',counts[kind]),element('span','',checkLabels[kind]));
      return count;
    }));
    $('pending-total').textContent = counts.other ? counts.other+' contrôle(s) au résultat à confirmer' : '';
  }
  const query = $('check-search').value.toLocaleLowerCase('fr').trim();
  const filter = $('check-status').value;
  const list = $('check-groups');
  const matching = rows.filter(r => (!filter || checkKind(r) === filter || (filter === 'resolved' && r.state === 'resolved')) &&
    (clientLabel(r.client)+' '+r.host+' '+r.name).toLocaleLowerCase('fr').includes(query));
  const signature = JSON.stringify([query,filter,matching]);
  if (list.dataset.rows === signature) { updateBulkBar(); return; }
  list.dataset.rows = signature;
  const groups = new Map();
  for (const row of matching) {
    const section = clientLabel(row.client);
    if (!groups.has(section)) groups.set(section, []);
    groups.get(section).push(row);
  }
  if (!groups.size) {
    list.replaceChildren(element('p','muted',rows.length ? 'Aucun contrôle ne correspond au filtre.' : 'Aucun contrôle du jour ni incident ouvert dans cette sélection.'));
    updateBulkBar();
    return;
  }
  const table = element('table','check-table');
  table.setAttribute('aria-labelledby','checks-title');
  const headings = table.createTHead().insertRow();
  for (const title of ['Tâche / source','Type de contrôle','Dernier signal','7 derniers jours','Détails']) {
    const th = element('th','',title);
    th.scope = 'col';
    headings.append(th);
  }
  const all = document.createElement('input');
  all.type = 'checkbox'; all.id = 'bulk-all';
  all.title = 'Cocher tous les contrôles affichés';
  all.setAttribute('aria-label',all.title);
  headings.firstElementChild.prepend(all);
  for (const domain of [...groups.keys()].sort((a,b)=>a.localeCompare(b,'fr'))) {
    const body = table.createTBody();
    body.className = 'check-group';
    const heading = element('th','family-title client-domain','Client : '+domain);
    heading.scope = 'rowgroup';
    heading.colSpan = 5;
    body.insertRow().append(heading);
    let lastService;
    for (const row of groups.get(domain).sort((a,b) => serviceLabel(a).localeCompare(serviceLabel(b),'fr') ||
      typeLabel(a).localeCompare(typeLabel(b),'fr') || a.name.localeCompare(b.name,'fr'))) {
      const service = serviceLabel(row);
      if (lastService !== service) {
        const title = element('th','service-title',service);
        title.colSpan = 5;
        body.insertRow().append(title);
        lastService = service;
      }
      const tr = body.insertRow(), name = tr.insertCell(), kind = checkKind(row);
      const label = row.state === 'resolved' ? 'Résolu' : row.missing && row.state === 'warning' ? 'En retard' :
        ({good:'Sans incident',warn:'Avertissement',bad:'Échec',other:'À confirmer'})[kind];
      const marker = element('span','signal '+kind);
      marker.title = label;
      marker.setAttribute('aria-label',label);
      marker.setAttribute('role','img');
      const box = document.createElement('input');
      box.type = 'checkbox';
      if (row.bulk_id) { box.dataset.check = ''; box.value = row.bulk_id; }
      else { box.disabled = true; box.title = 'Source du contrôle non identifiable'; }
      box.setAttribute('aria-label','Cocher '+row.name+' sur '+row.host+' · '+clientLabel(row.client));
      name.append(box,marker,element('span','check-name',row.name));
      if (row.host !== row.name) name.append(element('small','check-host',row.host));
      tr.insertCell().textContent = typeLabel(row);
      tr.insertCell().textContent = date(row.date);
      const history = tr.insertCell(), strip = element('span','signal-strip');
      const days = row.daily_history || [];
      for (const [day, state] of days) {
        const [kind, label] = dailyStates[state] || dailyStates.unknown;
        const dot = element('span','signal '+kind);
        dot.title = day.split('-').reverse().join('.')+' · '+label;
        dot.setAttribute('role','img');
        dot.setAttribute('aria-label',dot.title);
        strip.append(dot);
      }
      history.append(days.length ? strip : 'En attente de collecte');
      const inspect = inspectButton('Voir les détails de '+row.name+' sur '+row.host, () => {
        $('detail-days').replaceChildren(...days.map(([day, state]) => {
          const [kind, label] = dailyStates[state] || dailyStates.unknown;
          const item = element('li','','');
          item.append(element('span','signal '+kind),day.split('-').reverse().join('.')+' · '+label);
          return item;
        }));
        $('detail-signals').hidden = false;
        $('incident-analysis').hidden = true;
        $('detail-title').textContent = row.name;
        $('detail-context').textContent = 'Client : '+clientLabel(row.client)+' · Service : '+serviceLabel(row)+' · Type : '+typeLabel(row)+' · '+row.host+' · '+label+' · '+date(row.date);
        const entries = row.history.map(([stamp,event]) => element('li','',date(stamp)+' · '+(executionLabels[event] || 'À confirmer')));
        const content = entries.length ? element('ol','') : element('p','','Aucun signal reçu aujourd’hui.');
        content.append(...entries);
        $('detail-history').replaceChildren(content);
        $('check-detail').showModal();
        showMailDetail(row.detail_id);
      });
      tr.insertCell().append(inspect);
    }
  }
  list.replaceChildren(table);
  updateBulkBar();
}
$('check-search').addEventListener('input', () => renderChecks(current?.checks || []));
$('check-status').addEventListener('change', () => renderChecks(current?.checks || []));
function selectedCalendars() {
  return Array.from($('proposal-list').querySelectorAll(':checked'), input => input.value);
}
function updateProposalButton() {
  const count = selectedCalendars().length;
  $('activate-calendars').disabled = busy || !count;
  $('activate-calendars').textContent = count ? 'Activer la sélection ('+count+')' : 'Activer la sélection';
}
function renderProposals(rows) {
  const selected = new Set(selectedCalendars());
  renderPolicyList('proposal-list', rows, row => {
    const li = element('li',''), label = element('label','');
    const tick = document.createElement('input');
    tick.type='checkbox'; tick.value=row.token; tick.checked=selected.has(row.token);
    const title = element('span','',row.label);
    title.append(element('small','',row.observed+' jours observés sur '+row.expected+' attendus'+
      (row.header_dates ? ' · date déclarée utilisée pour '+row.header_dates+' jour(s)' : '')));
    label.append(tick,title,element('span','schedule-value',row.days.map(d=>weekdays[d]).join(' · ')+' à '+row.time));
    li.append(label);
    return li;
  });
  $('proposal-empty').hidden=rows.length>0;
  updateProposalButton();
}
$('proposal-list').addEventListener('change',updateProposalButton);
$('activate-calendars').addEventListener('click', () => {
  const tokens = selectedCalendars();
  if (!tokens.length) return;
  action($('activate-calendars'), async () => {
    await api('/api/schedules/activate',{tokens});
    $('proposal-status').textContent = tokens.length+' calendrier'+(tokens.length>1?'s activés.':' activé.');
  });
});

function loadSchedule(row) {
  $('scheduled-task').value = row.id;
  $('schedule-time').value = row.time;
  for (const day of $('schedule-days').querySelectorAll('input')) day.checked = row.days.includes(Number(day.value));
}
function renderMonitoring(state) {
  const data = state.monitoring;
  if (!data) return;
  renderProposals(data.suggestions || []);
  options($('scheduled-task'), data.tasks, $('scheduled-task').value, 'Choisis une tâche');
  const list = (rows, target, section) => renderPolicyList(target, rows, row => {
    const li = document.createElement('li');
    const title = document.createElement('span');
    title.textContent = section === 'schedules' ? row.label + ' · ' + row.days.map(d => weekdays[d]).join(', ') + ' à ' + row.time :
      row.task + ' · ' + row.sender + ' · « ' + row.family + ' » / « ' + row.phrase + ' » · ' + outcomeNames[row.outcome];
    li.append(title);
    if (section === 'schedules') li.append(button('Modifier', () => loadSchedule(row)));
    li.append(button('Retirer', el => action(el, async () => {
      await api('/api/'+section+'/remove', {id:row.id});
      $('monitoring-status').textContent = section === 'schedules' ? 'Calendrier retiré.' : 'Règle retirée.';
    })));
    return li;
  });
  list(data.schedules, 'schedules-list', 'schedules');
  list(data.rules, 'rules-list', 'rules');
  const sources = data.unknown.map(m => ({id:m.scope+'/'+m.id, label:m.subject+' · '+m.sender}));
  options($('rule-source'), sources, $('rule-source').value, 'Choisis un exemple');
  $('rule-empty').hidden = sources.length > 0;
  $('rule-editor').hidden = sources.length === 0;
  const suggestions = (state.report.preview?.suggestions || []).filter(s => data.unknown.some(m => m.id === s.id && m.scope === s.scope));
  renderPolicyList('rule-suggestions', suggestions, s => button('Créer une règle pour « '+s.subject+' »', () => {
    location.hash = 'reglages';
    $('rule-source').value = s.scope+'/'+s.id;
    $('rule-source').dispatchEvent(new Event('change'));
    $('rule-phrase').value = s.quote;
    $('rule-field').value = s.subject.includes(s.quote) ? 'subject' : 'body';
    requestAnimationFrame(() => $('rule-task').focus());
  }));
}
$('scheduled-task').addEventListener('change', () => {
  const row = current.monitoring.schedules.find(s => s.id === $('scheduled-task').value);
  if (row) loadSchedule(row);
});
$('schedule-form').addEventListener('submit', event => {
  event.preventDefault();
  action(event.submitter, async () => {
    const days = Array.from($('schedule-days').querySelectorAll(':checked'), e => Number(e.value));
    await api('/api/schedules/save', {id:$('scheduled-task').value, days, time:$('schedule-time').value});
    $('monitoring-status').textContent = 'Calendrier enregistré.';
  });
});
$('rule-source').addEventListener('change', () => {
  clearTest();
  const row = current.monitoring.unknown.find(m => m.scope+'/'+m.id === $('rule-source').value);
  $('rule-family').value = row?.subject.slice(0,240) || '';
  $('rule-task').value = $('rule-phrase').value = '';
});
$('rule-form').addEventListener('input', clearTest);
$('rule-form').addEventListener('submit', event => {
  event.preventDefault();
  clearTest();
  action(event.submitter, async () => {
    const [scope, source] = $('rule-source').value.split('/');
    const body = {scope, source};
    for (const k of ['family','task','phrase','field','outcome']) body[k] = $('rule-'+k).value;
    const revision = $('rule-form').dataset.edits;
    const result = await api('/api/rules/test', body);
    if ($('rule-form').dataset.edits !== revision) return;
    const list = document.createElement('ul');
    for (const row of result.rows) {
      const li = document.createElement('li');
      li.textContent = date(row.date)+' · '+row.subject+' — '+row.result;
      list.append(li);
    }
    $('rule-result').replaceChildren(result.message, list);
    ruleToken = result.token;
    $('activate-rule').hidden = !ruleToken;
  });
});
$('rule-form').addEventListener('input', () => { $('rule-form').dataset.edits = String(Number($('rule-form').dataset.edits || 0)+1); });
$('activate-rule').addEventListener('click', () => action($('activate-rule'), async () => {
  await api('/api/rules/activate', {token:ruleToken});
  clearTest();
  $('monitoring-status').textContent = 'Règle activée.';
}));

window.addEventListener('hashchange',view);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh(true);});
setInterval(()=>{if(!document.hidden && !busy && !$('application').hidden)refresh(true);},3000);
refresh();
