'use strict';
const $ = id => document.getElementById(id);
let csrf = '', current = null, settingsDirty = false, settingsLoaded = false, busy = false, profileChoice = null;
const date = value => value ? new Date(value).toLocaleString('fr-CH', {dateStyle:'short',timeStyle:'short'}) : '—';
function notice(text, error = false) { $('notice').textContent = text; $('notice').hidden = !text; $('notice').classList.toggle('error', error); }
function view() { const name = ['bilan','rapport','reglages'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'bilan'; document.querySelectorAll('.view').forEach(section => section.hidden = section.id !== 'view-' + name); document.querySelectorAll('[data-view]').forEach(a => { if(a.dataset.view === name) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current'); }); }
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
      text.append(element('small','issue-client',clientLabel(row.client)));
      const when = element('time','issue-date',date(row.date));
      when.dateTime = row.date;
      text.className = 'issue-name';
      text.prepend(element('span','sr-only',row.severity === 'open' ? 'Échec — ' : 'Avertissement — '));
      label.append(checkbox, when, text);
      item.dataset.kind = row.severity === "open" ? "bad" : "warn";
      item.append(label);
      if (row.analysis?.state === 'ready') {
        const note = element('details','incident-note');
        note.dataset.signal = row.id;
        note.open = expanded.has(row.id);
        note.append(element('summary','','Analyse IA · '+row.analysis.constat),
          element('p','','Élément relevé : « '+row.analysis.preuve+' »'),
          element('p','','Vérification proposée : '+row.analysis.verification));
        item.append(note);
      } else if (row.analysis) {
        const statuses = {pending:'Analyse IA en attente.', error:'Analyse IA différée. Nouvel essai automatique.',
          configure:'Pour analyser cet incident, connecte ChatGPT et choisis un modèle dans les réglages.'};
        const reasons = {usage_limit:'Limite ChatGPT atteinte. L’analyse reprendra après un délai.',
          invalid_analysis:'La réponse IA ou sa citation n’a pas pu être validée. Un nouvel essai est prévu.',
          login_required:'Reconnecte le compte ChatGPT dans les réglages.', model_unavailable:'Actualise les modèles et choisis un modèle disponible.'};
        item.append(element('p','incident-note muted', reasons[row.analysis.reason] || statuses[row.analysis.state]));
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
const familyLabels = new Map([
  ['Sauvegardes',['synology-backup','synology-abb','synology-restore','synology-integrity','pbs','pve']],
  ['Stockage',['synology-disks','synology-capacity']],
  ['Réplication',['synology-replication','synology-snapshot']],
  ['Disponibilité',['uptime','synology-abb-connectivity','pve-ha','synology-ha']],
  ['Sécurité',['account-security','synology-firewall','openvas','wazuh','pmg']],
  ['Alimentation',['ups','ups-monitoring','ups-snmp']],
  ['Maintenance',['synology-log','synology-cms','synology-dsm-update']],
  ['Tâches planifiées',['synology-scheduler']], ['Impression',['printer']],
  ['Intégration continue',['github-actions']], ['Contrôles personnalisés',['custom']]
].flatMap(([label, keys]) => keys.map(key => [key,label])));
const clientLabel = domain => domain || 'Domaine indéterminé';
function renderClientView(state) {
  const picker = $('client-filter');
  const counts = state.summary?.clients_today || {};
  const rows = state.checks || [], issues = state.incidents || [];
  const domains = new Set([...Object.keys(counts), ...rows.map(r => r.client || ''), ...issues.map(r => r.client || '')]);
  const selected = picker.value;
  if (selected !== '*') domains.add(selected);
  const items = [...domains].sort((a,b) => clientLabel(a).localeCompare(clientLabel(b),'fr'));
  const signature = JSON.stringify(items);
  if (picker.dataset.domains !== signature) {
    picker.replaceChildren(new Option('Tous les clients','*'), ...items.map(d => new Option(clientLabel(d),d)));
    picker.value = selected;
    picker.dataset.domains = signature;
  }
  const all = selected === '*';
  $('message-count').textContent = all ? state.summary?.today_messages ?? '—' : counts[selected]?.messages || 0;
  $('unknown-count').textContent = all ? state.summary?.today_unknown ?? '—' : counts[selected]?.unknown || 0;
  renderIncidents(issues.filter(r => all || (r.client || '') === selected));
  renderChecks(rows);
}
$('client-filter').addEventListener('change', () => renderClientView(current));
$('check-grouping').addEventListener('change', () => renderChecks(current.checks || []));
function renderChecks(rows) {
  const selectedClient = $('client-filter').value;
  if (selectedClient !== '*') rows = rows.filter(r => (r.client || '') === selectedClient);
  const byClient = $('check-grouping').value === 'client';
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
  const matching = rows.filter(r => (!filter || checkKind(r) === filter) &&
    (clientLabel(r.client)+' '+r.host+' '+r.name).toLocaleLowerCase('fr').includes(query));
  const signature = JSON.stringify([query,filter,byClient,matching]);
  if (list.dataset.rows === signature) return;
  list.dataset.rows = signature;
  const groups = new Map();
  for (const row of matching) {
    const family = row.missing ? 'Rapports attendus' : familyLabels.get(row.family) || row.family || 'Autres contrôles';
    const section = byClient ? clientLabel(row.client) : family;
    if (!groups.has(section)) groups.set(section, []);
    groups.get(section).push(row);
  }
  if (!groups.size) {
    list.replaceChildren(element('p','muted',rows.length ? 'Aucun contrôle ne correspond au filtre.' : 'Aucun contrôle à afficher pour le moment.'));
    return;
  }
  const table = element('table','check-table');
  table.setAttribute('aria-labelledby','checks-title');
  const headings = table.createTHead().insertRow();
  for (const title of ['Contrôle','Dernier signal','Historique du jour','Détails']) {
    const th = element('th','',title);
    th.scope = 'col';
    headings.append(th);
  }
  for (const family of [...groups.keys()].sort((a,b)=>a.localeCompare(b,'fr'))) {
    const body = table.createTBody();
    body.className = 'check-group';
    const heading = element('th',byClient ? 'family-title client-domain' : 'family-title',family);
    heading.scope = 'rowgroup';
    heading.colSpan = 4;
    body.insertRow().append(heading);
    for (const row of groups.get(family)) {
      const tr = body.insertRow(), name = tr.insertCell(), kind = checkKind(row);
      const label = row.missing && row.state === 'warning' ? 'En retard' :
        ({good:'Sans incident',warn:'Avertissement',bad:'Échec',other:'À confirmer'})[kind];
      const marker = element('span','signal '+kind);
      marker.title = label;
      marker.setAttribute('aria-label',label);
      marker.setAttribute('role','img');
      name.append(marker,element('span','check-name',row.name),element('small','check-host',byClient ? row.host : row.host+' · '+clientLabel(row.client)));
      tr.insertCell().textContent = date(row.date);
      const history = tr.insertCell(), strip = element('span','signal-strip');
      for (const [stamp,event] of row.history) {
        const dot = element('span','signal '+(({success:'good',failure:'bad',warning:'warn'})[event] || 'other'));
        dot.title = date(stamp)+' · '+(executionLabels[event] || 'À confirmer');
        dot.setAttribute('role','img');
        dot.setAttribute('aria-label',dot.title);
        strip.append(dot);
      }
      history.append(row.history.length ? strip : '—');
      const inspect = button('', () => {
        $('detail-title').textContent = row.name;
        $('detail-context').textContent = clientLabel(row.client)+' · '+row.host+' · '+label+' · '+date(row.date);
        const entries = row.history.map(([stamp,event]) => element('li','',date(stamp)+' · '+(executionLabels[event] || 'À confirmer')));
        const content = entries.length ? element('ol','') : element('p','','Aucun signal reçu aujourd’hui.');
        content.append(...entries);
        $('detail-history').replaceChildren(content);
        $('check-detail').showModal();
      });
      inspect.className = 'inspect';
      inspect.title = 'Voir les détails de '+row.name+' sur '+row.host;
      inspect.setAttribute('aria-label',inspect.title);
      tr.insertCell().append(inspect);
    }
  }
  list.replaceChildren(table);
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
