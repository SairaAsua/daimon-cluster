'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const zero = value => !value || value.startsWith('0001-');
  const localDay = value => value.getFullYear()+'-'+String(value.getMonth()+1).padStart(2,'0')+'-'+String(value.getDate()).padStart(2,'0');
  let state = null, view = 'today', selected = null, busy = false, editing = null, onboardingShown = false;
  const formOperations = new WeakMap();
  const errors = {
    agenda_access_denied:'Entra con la identidad vinculada a esta agenda.',
    agenda_provider_unavailable:'No pudimos comunicarnos con la agenda. Tus cambios sin guardar siguen aquí.',
    agenda_provider_denied:'El motor de tareas no pudo autorizar esta operación.',
    agenda_not_initialized:'Primero activa nuestra agenda.',
    agenda_operation_uncertain:'La respuesta no está confirmada. Actualiza la agenda para comprobar el resultado antes de volver a guardar.',
    agenda_operation_conflict:'Esta operación ya tenía otros datos. Actualiza la agenda.',
    agenda_task_changed:'La tarea cambió en otra sesión. Actualiza la agenda antes de editarla.',
    agenda_invalid_timezone_or_time:'La hora no existe en esta zona horaria. Revisa el horario.',
    agenda_title_required:'Escribe un título.', agenda_invalid_date:'Revisa la fecha.',
    agenda_invalid_time:'La hora necesita una fecha válida.'
  };
  function message(value, error=false) {$('status').textContent=value;$('status').classList.toggle('error',error);}
  function element(tag,text,cls) {const e=document.createElement(tag);if(text!=null)e.textContent=text;if(cls)e.className=cls;return e;}
  async function request(path,options) {
    const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),25000);
    try {
      const response=await fetch(path.startsWith('/')?path:'/agenda/api/'+path,{cache:'no-store',credentials:'same-origin',...options,signal:controller.signal});
      const data=await response.json();
      if(!response.ok){const e=new Error(errors[data.error]||'No se pudo completar la operación. Actualiza para comprobar el estado.');e.status=response.status;e.code=data.error;throw e;}
      return data;
    } catch(error) {
      if(error.name==='AbortError')throw new Error('La respuesta tardó más de lo esperado. Conservamos lo escrito. Actualiza para comprobar si se guardó.');
      if(!error.status)throw new Error('No pudimos recibir la respuesta. Conservamos lo escrito. Actualiza para comprobar si se guardó.');
      throw error;
    } finally {clearTimeout(timeout);}
  }
  async function command(action,payload,owner) {
    if(busy)throw new Error('Espera a que termine la operación actual.');
    let key;
    if(owner) {
      const fingerprint=JSON.stringify([action,payload]), old=formOperations.get(owner);
      if(old?.uncertain&&old.fingerprint!==fingerprint)throw new Error('Hay un guardado sin confirmar. Actualiza la agenda para comprobar el resultado antes de crear otra tarea.');
      key=old?.fingerprint===fingerprint?old.key:crypto.randomUUID();
      formOperations.set(owner,{key,fingerprint});
    } else key=crypto.randomUUID();
    busy=true; document.querySelectorAll('button').forEach(b=>b.disabled=true);
    try {
      const result=await request('command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,payload:{...payload,operation_id:key}})});
      if(owner)formOperations.delete(owner);
      return result;
    } catch(error) {
      if(owner){if(error.status&&error.status<500&&error.code!=='agenda_operation_uncertain')formOperations.delete(owner);else formOperations.get(owner).uncertain=true;}
      throw error;
    } finally {busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);}
  }
  async function refresh() {
    try {
      const fresh=await request('state');state=fresh;
      $('initialize').hidden=fresh.initialized;$('workspace').hidden=!fresh.initialized;
      $('auth').hidden=true;message('');
      if(fresh.initialized){render();if(!fresh.calendar.setup_complete&&!onboardingShown){onboardingShown=true;calendarDialog();}}
    } catch(error) {if(error.status===401||error.status===403){state=null;selected=null;$('workspace').hidden=true;$('initialize').hidden=true;$('task-list').replaceChildren();$('project-list').replaceChildren();$('detail-description').textContent='';$('observations').replaceChildren();document.querySelectorAll('dialog[open]').forEach(d=>d.close());message('La sesión ya no tiene acceso a esta agenda. Vuelve a entrar para continuar.',true);const link=element('a',' Volver a entrar');link.href='/agenda/';$('status').append(link);}else message(error.message+(state?' La vista anterior puede estar desactualizada.':''),true);}
  }
  function projectName(id){return state.projects.find(p=>p.id===id)?.title||'Proyecto';}
  function taskDay(t){return !zero(t.start_date)?localDay(new Date(t.start_date)):!zero(t.due_date)?t.due_date.slice(0,10):null;}
  function when(t){
    if(!zero(t.start_date))return new Intl.DateTimeFormat('es',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'}).format(new Date(t.start_date));
    const day=taskDay(t);return day?new Intl.DateTimeFormat('es',{day:'numeric',month:'long',timeZone:'UTC'}).format(new Date(day+'T12:00:00Z'))+' · sin hora':'Sin fecha';
  }
  function render() {
    const chosen=$('project-filter').value;
    $('project-filter').replaceChildren(new Option('Todos los proyectos',''),...state.projects.map(p=>new Option(p.title,String(p.id))));
    if(state.projects.some(p=>String(p.id)===chosen))$('project-filter').value=chosen;
    const titles={today:['UN PASO A LA VEZ','Para hoy'],pending:['LO QUE QUEREMOS HACER','Pendientes'],calendar:['FECHAS IMPORTANTES','En el horizonte'],projects:['CADA COSA EN SU LUGAR','Nuestros proyectos']};
    $('view-caption').textContent=titles[view][0];$('view-title').textContent=titles[view][1];
    const search=$('search').value.toLocaleLowerCase(), project=$('project-filter').value, done=$('show-done').checked;
    let rows=state.tasks.filter(t=>(done||!t.done)&&(!project||String(t.project_id)===project)&&(!search||(t.title+' '+t.description).toLocaleLowerCase().includes(search)));
    const today=localDay(new Date());
    if(view==='today')rows=rows.filter(t=>taskDay(t)&&taskDay(t)<=today);
    if(view==='calendar')rows=rows.filter(t=>taskDay(t));
    rows.sort((a,b)=>(taskDay(a)||'9999').localeCompare(taskDay(b)||'9999')||b.priority-a.priority||a.id-b.id);
    $('task-list').hidden=view==='projects';$('project-list').hidden=view!=='projects';
    $('task-count').textContent=view==='projects'?`${state.projects.length} proyectos`:`${rows.length} tareas`;
    if(view==='projects') {
      $('project-list').replaceChildren(...state.projects.map(p=>{
        const b=element('button',null,'project-card');b.type='button';b.append(element('span',p.title),element('span',`${state.tasks.filter(t=>t.project_id===p.id&&!t.done).length} pendientes`));
        b.addEventListener('click',()=>{$('project-filter').value=String(p.id);setView('pending');});return b;
      }));
    } else if(!rows.length) {
      const empty=element('div',null,'empty');empty.append(element('h3',view==='today'?'Por aquí está despejado.':'Todavía no hay tareas en esta vista.'),element('p',view==='today'?'Puedes mirar Pendientes o anotar algo nuevo.':'Lo que anotes aparecerá aquí.'));
      $('task-list').replaceChildren(empty);
    } else $('task-list').replaceChildren(...rows.map(taskRow));
    const c=state.calendar;
    $('calendar-state').textContent=c.connected?`${c.email} · conectado.`:c.email?`${c.email} · conexión automática pendiente.`:'Google Calendar todavía no está conectado.';
    $('calendar-settings').textContent='Configurar Google Calendar';
  }
  function setView(next){view=next;document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));render();}
  function taskRow(t) {
    const row=element('article',null,'task-row'+(t.done?' done':''));
    const check=element('button',t.done?'✓':'○','task-check');check.type='button';check.setAttribute('aria-label',(t.done?'Reabrir ':'Terminar ')+t.title);
    check.addEventListener('click',()=>complete(t,check));
    const open=element('button',null,'task-open');open.type='button';open.append(element('span',t.title,'task-title'),element('span',projectName(t.project_id)+(t.priority>=3?' · prioridad alta':''),'task-info'));
    open.addEventListener('click',()=>details(t));row.append(check,open,element('span',when(t),'task-date'));return row;
  }
  async function complete(t,button) {
    try {const r=await command('task-update',{task_id:t.id,revision:t.revision,done:!t.done},button);state.tasks=state.tasks.map(x=>x.id===t.id?r.task:x);render();if(selected?.id===t.id){selected=r.task;$('complete-task').textContent=selected.done?'Reabrir tarea':'Marcar terminada';}message(t.done?'Tarea reabierta.':'Tarea terminada.');}
    catch(e){message(e.message,true);}
  }
  function googleUrl(t) {
    if(!taskDay(t))return null;
    const stamp=s=>new Date(s).toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z');
    let dates;
    if(!zero(t.start_date)&&!zero(t.end_date))dates=stamp(t.start_date)+'/'+stamp(t.end_date);
    else {const day=taskDay(t),end=new Date(Date.parse(day)+86400000).toISOString().slice(0,10);dates=day.replaceAll('-','')+'/'+end.replaceAll('-','');}
    const p=new URLSearchParams({action:'TEMPLATE',text:t.title,details:t.description,dates});
    if(state.calendar.email)p.set('authuser',state.calendar.email);
    return 'https://calendar.google.com/calendar/render?'+p;
  }
  async function details(t) {
    selected=t;$('detail-title').textContent=t.title;$('detail-description').textContent=t.description;$('detail-meta').textContent=projectName(t.project_id)+' · '+when(t);
    $('complete-task').textContent=t.done?'Reabrir tarea':'Marcar terminada';
    const url=googleUrl(t),connected=state.calendar.connected;$('google-event').hidden=!url||connected;$('google-explanation').hidden=!url||connected;$('sync-calendar').hidden=!url||!connected;if(url)$('google-event').href=url;$('detail-status').textContent='';
    $('observations').textContent='Leyendo observaciones…';$('observation-form').reset();$('observation-error').textContent='';$('detail-dialog').showModal();
    await observations(t.id);
  }
  async function observations(id) {
    try {const r=await request('observations?task_id='+id);if(selected?.id!==id)return;
      $('observations').replaceChildren(...r.observations.map(o=>{const row=element('article',null,'observation');const time=element('time',new Intl.DateTimeFormat('es',{dateStyle:'medium',timeStyle:'short'}).format(new Date(o.created)));time.dateTime=o.created;row.append(time,element('p',o.text));return row;}));
      if(!r.observations.length)$('observations').append(element('p','Aquí iremos dejando lo que pase.','support'));
    }catch(e){$('observations').textContent=e.message;}
  }
  function taskForm(task=null){editing=task;const f=$('task-form');f.reset();delete f.dataset.dirty;formOperations.delete(f);f.elements.project_id.replaceChildren(...state.projects.filter(p=>!p.is_archived).map(p=>new Option(p.title,String(p.id))));if($('project-filter').value)f.elements.project_id.value=$('project-filter').value;
    $('task-form-title').textContent=task?'Editar tarea':'Nueva tarea';
    if(task){for(const key of ['title','description','project_id','priority'])f.elements[key].value=task[key];f.elements.date.value=taskDay(task)||'';if(!zero(task.start_date)){const d=new Date(task.start_date);f.elements.date.value=localDay(d);f.elements.time.value=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');f.elements.duration.value=Math.round((Date.parse(task.end_date)-Date.parse(task.start_date))/60000);}}
    $('task-error').textContent='';$('task-dialog').showModal();
  }
  $('new-task').addEventListener('click',()=>taskForm());
  $('task-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget,v=Object.fromEntries(new FormData(f));v.project_id=Number(v.project_id);v.duration=Number(v.duration);v.priority=Number(v.priority);v.timezone=zone;
    try {const r=await command(editing?'task-edit':'task-create',editing?{...v,task_id:editing.id,revision:editing.revision}:v,f);state.tasks=editing?state.tasks.map(t=>t.id===editing.id?r.task:t):[...state.tasks,r.task];editing=null;f.reset();delete f.dataset.dirty;$('task-dialog').close();setView('pending');message(r.calendar?.status==='synced'?'Tarea guardada y evento confirmado en Google.':r.calendar?.status==='pending'?'Tarea guardada. La actualización en Google sigue pendiente.':'Tarea guardada en nuestra agenda.');}catch(e){$('task-error').textContent=e.message;}
  });
  $('observation-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget,id=selected.id;
    try{await command('observation-add',{task_id:id,text:new FormData(f).get('text')},f);f.reset();$('observation-error').textContent='';await observations(id);}catch(e){$('observation-error').textContent=e.message;}
  });
  $('project-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;try{const r=await command('project-create',{title:new FormData(f).get('title')},f);state.projects.push(r.project);f.reset();$('project-dialog').close();setView('projects');}catch(e){$('project-error').textContent=e.message;}});
  function calendarDialog(){const f=$('calendar-form');f.reset();delete f.dataset.dirty;f.elements.email.value=state.calendar.email;f.elements.email.disabled=state.calendar.connected;$('calendar-error').textContent='';$('calendar-browser').hidden=true;$('calendar-disconnect').hidden=!state.calendar.connected;$('calendar-connect').hidden=state.calendar.connected;$('calendar-later').textContent=state.calendar.connected?'Volver a la agenda':'Continuar sin Google';$('calendar-config-status').textContent=state.calendar.connected?'Esta agenda ya tiene acceso a la cuenta indicada.':state.calendar.available?'Google te pedirá elegir la cuenta y autorizar Calendar.':'La conexión con Google necesita que el operador configure el cliente de la aplicación. Puedes guardar la cuenta preferida y continuar con la agenda.';$('calendar-connect').textContent=state.calendar.available?'Conectar Google Calendar':'Guardar cuenta preferida';$('calendar-dialog').showModal();}
  $('calendar-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;try{const r=await command('calendar-account',{email:new FormData(f).get('email')},f);state.calendar=r.calendar;if(!state.calendar.available){const skipped=await command('calendar-skip',{},f);state.calendar=skipped.calendar;message('Cuenta preferida guardada. La autorización de Google está pendiente.');$('calendar-dialog').close();render();return;}if(tg?.initData){$('calendar-browser').hidden=false;$('calendar-connect').hidden=true;$('calendar-config-status').textContent='Cuenta guardada. Abre el navegador para autorizar Google; después vuelve a esta mini app y pulsa Actualizar.';delete f.dataset.dirty;return;}const start=await request('/agenda/google/start',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});delete f.dataset.dirty;window.location.assign(start.authorization_url);}catch(e){$('calendar-error').textContent=e.message;}});
  $('calendar-browser').addEventListener('click',()=>{const url=location.origin+'/agenda/?setup=calendar';if(typeof tg?.openLink==='function')tg.openLink(url);else window.open(url,'_blank','noopener,noreferrer');});
  $('calendar-later').addEventListener('click',async()=>{try{if(!state.calendar.connected){const r=await command('calendar-skip',{},$('calendar-later'));state.calendar=r.calendar;}$('calendar-dialog').close();render();}catch(e){$('calendar-error').textContent=e.message;}});
  $('calendar-disconnect').addEventListener('click',async()=>{try{const r=await command('calendar-disconnect',{},$('calendar-disconnect'));state.calendar=r.calendar;$('calendar-dialog').close();render();message('La agenda dejó de usar Google. Puedes revocar también el permiso desde tu cuenta de Google.');}catch(e){$('calendar-error').textContent=e.message;}});
  $('sync-calendar').addEventListener('click',async()=>{try{const r=await command('calendar-sync',{task_id:selected.id},$('sync-calendar'));$('detail-status').textContent=r.calendar.status==='synced'?'Evento confirmado en Google Calendar.':'El evento todavía no está confirmado.';}catch(e){$('detail-status').textContent=e.message;}});
  $('edit-task').addEventListener('click',()=>{const t=selected;$('detail-dialog').close();taskForm(t);});
  $('complete-task').addEventListener('click',()=>complete(selected,$('complete-task')));
  $('new-project').addEventListener('click',()=>{$('project-form').reset();$('project-error').textContent='';$('project-dialog').showModal();});
  $('calendar-settings').addEventListener('click',calendarDialog);
  $('initialize-button').addEventListener('click',async()=>{try{await command('init',{},$('initialize-button'));await refresh();}catch(e){message(e.message,true);}});
  $('refresh').addEventListener('click',refresh);
  document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.view)));
  document.querySelectorAll('form').forEach(f=>f.addEventListener('input',()=>f.dataset.dirty='true'));
  document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>{const d=$(b.dataset.close),f=d.querySelector('form');if(f?.dataset.dirty==='true'&&!confirm('¿Cerrar este formulario? Lo que todavía no guardaste se perderá.'))return;d.close();}));
  document.querySelectorAll('dialog').forEach(d=>d.addEventListener('cancel',e=>{const f=d.querySelector('form');if(f?.dataset.dirty==='true'&&!confirm('¿Cerrar sin guardar?'))e.preventDefault();}));
  ['search','project-filter','show-done'].forEach(id=>$(id).addEventListener(id==='search'?'input':'change',()=>state&&render()));
  $('timezone').textContent='Los horarios se guardan con tu zona: '+zone+'.';
  const now=new Date();$('today-weekday').textContent=new Intl.DateTimeFormat('es',{weekday:'long'}).format(now);$('today-number').textContent=now.getDate();$('today-month').textContent=new Intl.DateTimeFormat('es',{month:'long'}).format(now);
  const tg=window.Telegram?.WebApp;if(tg){tg.ready();tg.expand();}
  window.addEventListener('beforeunload',e=>{if(document.querySelector('dialog[open] form[data-dirty=true]')){e.preventDefault();e.returnValue='';}});
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&state?.initialized&&!busy&&!document.querySelector('dialog[open] form[data-dirty=true]'))refresh();});
  refresh().then(()=>{const result=new URLSearchParams(location.search).get('calendar');if(result==='connected')message('Google Calendar conectado. Puedes sincronizar las tareas con fecha que ya tenías.');else if(result==='failed'||result==='denied')message('La conexión con Google no se completó. Revisa la cuenta elegida y vuelve a intentarlo desde Configurar Google Calendar.',true);});
})();
