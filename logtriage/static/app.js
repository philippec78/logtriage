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
  const headings = ['À EXAMINER EN PRIORITÉ', 'PROBLÈMES TOUJOURS OUVERTS', 'RÉTABLIS DANS LES DERNIÈRES 24 H'];
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
function incidentSelection() {
  const selected = current?.incidents?.find(row => row.id === $('incident-picker').value);
  $('resolve-incident').disabled = !selected || busy || current?.report?.job?.state === 'running';
  $('incident-detail').textContent = selected ? selected.summary + ' · Dernier signal le ' + date(selected.date) : '';
}
function renderIncidents(rows) {
  const picker = $('incident-picker');
  const fingerprint = JSON.stringify(rows);
  if (picker.dataset.rows !== fingerprint) {
    const previous = picker.value;
    picker.replaceChildren(new Option(rows.length ? 'Choisis un incident' : 'Aucun incident ouvert', ''));
    for (const row of rows) {
      const prefix = row.severity === 'open' ? 'Échec' : 'Avertissement';
      picker.add(new Option(prefix + ' — ' + row.summary, row.id));
    }
    if (rows.some(row => row.id === previous)) picker.value = previous;
    picker.dataset.rows = fingerprint;
  }
  picker.disabled = !rows.length;
  $('incident-count').textContent = '(' + rows.length + ')';
  incidentSelection();
}
function render(state) {
  current=state; csrf=state.csrf;
  $('login-view').hidden=true; $('application').hidden=false;
  $('version').textContent='Logtriage '+state.version;
  const collection=state.status?.collection, status=state.status?.state;
  const stale=state.status && Date.now()-Date.parse(state.status.last_cycle_at)>Math.max(900,state.status.poll_seconds*3)*1000;
  $('collection-status').textContent=!state.status ? 'La première collecte n’est pas encore disponible.' : stale ? 'La dernière collecte est ancienne. Vérifie le service avant de te fier au bilan.' : status !== 'ok' ? 'Collecte à vérifier : le bilan reflète les données disponibles.' : collection?.pending ? `Collecte en cours : ${collection.pending} emails restent à analyser.` : 'Collecte à jour · boîte consultée en lecture seule';
  $('message-count').textContent=state.summary?.total_messages?.toLocaleString('fr-CH') ?? '—';
  $('unknown-count').textContent=state.summary?.unrecognized_messages ?? '—'; $('last-collection').textContent=date(state.status?.last_cycle_at);
  showReport($('latest-digest'), state.latest_digest || 'Le bilan apparaîtra après la première collecte.');
  renderIncidents(state.incidents || []);
  settings(state);
  const preview=state.report.preview, job=state.report.job, running=job.state==='running';
  $('prepare').disabled=running || busy; $('prepare').textContent=running&&job.kind==='preview'?'Préparation en cours…':'Préparer le rapport'; $('prepare').setAttribute('aria-busy',String(running&&job.kind==='preview'));
  $('recipient-summary').textContent=state.settings.recipient?'Destinataire : '+state.settings.recipient:'Renseigne le destinataire dans les réglages.';
  $('ai-plan-status').textContent=state.chatgpt.connected?'Utilise ton abonnement ChatGPT.':'Connecte ChatGPT dans les réglages pour ajouter une analyse.';
  $('mail-headers').hidden=!preview; $('report-preview').classList.toggle('empty',!preview);
  $('preview-date').textContent=preview?'Préparé le '+date(preview.created_at):'';
  showReport($('report-preview'), preview?.body || 'Choisis le type de bilan, puis prépare l’aperçu.');
  $('preview-to').textContent=preview?.recipient||''; $('preview-subject').textContent=preview?.subject||'';
  $('ai-warning').hidden=!preview?.ai?.message; $('ai-warning').textContent=preview?.ai?.message||'';
  const stalePreview = preview && (preview.resolution_count || 0) !== (state.summary?.resolution_count || 0);
  $('send').disabled=!preview || stalePreview || running || preview.delivery!=='not_sent' || busy;
  $('send').textContent=running&&job.kind==='send'?'Envoi en cours…':'Envoyer cet aperçu';
  $('delivery-status').textContent=preview?.delivery_message || (preview?.ai?.state==='completed'?'Analyse ChatGPT ajoutée. Aucun envoi effectué.':'Aucun envoi effectué depuis cet aperçu.');
  if (stalePreview && preview.delivery === 'not_sent') $('delivery-status').textContent = 'Un incident a été validé. Prépare un nouvel aperçu pour l’envoyer.';
  $('last-send').textContent=state.report.last_send?'Dernière acceptation SMTP : '+date(state.report.last_send.accepted_at)+' pour '+state.report.last_send.recipient:'';
  if(job.state==='error') notice(job.message,true);
  view();
}
async function refresh(quiet = false) { try {render(await api('/api/state'));} catch(error) {if($('application').hidden) {$('login-view').hidden=false;if(error instanceof TypeError)$('login-error').textContent='Le serveur est injoignable. Réessaie la connexion.';} else if(!quiet) notice(error.message,true);} }
async function action(button, fn) { if(busy) return; busy=true; button.disabled=true; button.setAttribute('aria-busy','true'); notice(''); try{await fn();}catch(error){notice(error.message,true);}finally{busy=false;button.disabled=false;button.removeAttribute('aria-busy');await refresh(true);} }
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$('login-error').textContent='';try{const result=await api('/api/login',{username:$('username').value,password:$('password').value});csrf=result.csrf;$('password').value='';await refresh();}catch(error){$('login-error').textContent=error.message;}finally{button.disabled=false;}});
$('logout').addEventListener('click',()=>action($('logout'),async()=>{await api('/api/logout',{});current=null;settingsDirty=false;settingsLoaded=false;$('application').hidden=true;$('login-view').hidden=false;}));
$('incident-picker').addEventListener('change', incidentSelection);
$('manage-incidents').addEventListener('click', () => {
  $('incident-panel').open = true;
  requestAnimationFrame(() => $('incident-picker').focus());
});
$('resolve-incident').addEventListener('click', () => {
  const selected = current.incidents.find(row => row.id === $('incident-picker').value);
  if (!selected) return;
  action($('resolve-incident'), async () => {
    await api('/api/resolve', {id: selected.id});
    $('resolution-status').textContent = 'Résolution enregistrée pour ' + selected.summary;
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
window.addEventListener('hashchange',view);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh(true);});
setInterval(()=>{if(!document.hidden && !busy && !$('application').hidden)refresh(true);},3000);
refresh();
