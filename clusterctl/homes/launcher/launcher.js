/* Catalog metadata is text and navigation, never executable code or authority. */
"use strict";
(async () => {
  const byId=id=>document.getElementById(id), webapp=window.Telegram?.WebApp;
  try {
    if(await window.DaimonMiniAppLaunch?.(JSON.parse(byId('miniapp-routes')?.textContent||'null')))return;
  } catch {
    byId('notice').textContent='No pudimos recuperar esta apertura de Telegram. Cerrá y volvé a abrir la app.';
    return;
  }
  const storageKey='dm.launcher.favorites/v1';
  let receiverChoice='';
  try{receiverChoice=localStorage.getItem('dm.launcher.receiver/v1')||'';}catch{}
  let entries=[], favorites=new Set(), favoritesOnly=false, pending=null;
  let attention=null, attentionPending=false;
  try{const saved=JSON.parse(localStorage.getItem(storageKey)||'[]');if(Array.isArray(saved))favorites=new Set(saved.filter(x=>typeof x==='string').slice(0,256));}catch{}
  const icons={
    nexus:'<circle cx="16" cy="16" r="5"/><ellipse cx="16" cy="16" rx="14" ry="6" transform="rotate(-40 16 16)"/><path d="M16 1v5m0 20v5M1 16h5m20 0h5"/>',
    sessions:'<rect x="3" y="4" width="26" height="24" rx="4"/><path d="M3 11h26M8 8h1m3 0h1M7 20h4l3-5 4 9 3-6h4"/>',
    homemaker:'<path d="m2 15 14-12 14 12M6 12v17h20V12M12 29V18h8v11"/><circle cx="23" cy="7" r="3"/>',
    app:'<rect x="3" y="3" width="10" height="10" rx="3"/><rect x="19" y="3" width="10" height="10" rx="3"/><rect x="3" y="19" width="10" height="10" rx="3"/><path d="M19 24h10m-5-5v10"/>'};
  // Web targets are qualified by the gateway's configured owner application,
  // not promoted from arbitrary published links. Never execute URL schemes.
  function safeURL(entry){try{const u=new URL(entry.url);return u.protocol==='https:'&&(u.host==='t.me'||entry.launch==='web')&&!u.username&&!u.password&&!u.hash?u:null;}catch{return null;}}
  function resolvedEntry(original){
    const chosen=original.application_mode==='paired'&&(original.receivers||[]).find(r=>r.home===receiverChoice&&safeURL({url:r.url,launch:'web'}));
    return chosen?{...original,url:chosen.url,receiver_bot:chosen.bot,available:true,launch:'web'}:original;
  }
  function render(){
    const choices=new Map();
    for(const e of entries)for(const r of e.receivers||[])if(r&&typeof r.home==='string'&&typeof r.name==='string'&&safeURL({url:r.url,launch:'web'}))choices.set(r.home,r.name);
    byId('receiver-label').hidden=!choices.size;
    const picker=byId('receiver-choice');picker.replaceChildren(new Option('Elegí tu pareja',''),...[...choices].map(([home,name])=>new Option(name,home)));picker.value=receiverChoice;
    const term=byId('search').value.toLocaleLowerCase();
    const shown=entries.filter(e=>(!favoritesOnly||favorites.has(e.id))&&[e.title,e.summary,e.author].join(' ').toLocaleLowerCase().includes(term));
    byId('count').textContent=shown.length+' / '+entries.length;
    byId('apps').replaceChildren(...shown.map(original=>{
      const entry=resolvedEntry(original);
      const row=document.createElement('li');row.className='app';
      const link=document.createElement('a');link.className='app-link';link.href=entry.url;
      if(entry.available===false){link.removeAttribute('href');link.setAttribute('aria-disabled','true');}
      link.addEventListener('click',event=>{if(entry.available===false){event.preventDefault();return;}if(new URL(entry.url).host==='t.me'&&webapp?.openTelegramLink){event.preventDefault();webapp.openTelegramLink(entry.url);}});
      const icon=document.createElement('span');icon.className='app-icon';icon.setAttribute('aria-hidden','true');
      const key=/nexus/i.test(entry.title)?'nexus':/sessions/i.test(entry.title)?'sessions':/home\s*maker/i.test(entry.title)?'homemaker':'app';
      icon.innerHTML='<svg viewBox="0 0 32 32">'+icons[key]+'</svg>';
      if(attention?.symbol && matchesAttention(entry)){
        const dot=document.createElement('span');dot.className='attention-dot';dot.textContent=attention.symbol;icon.append(dot);
        link.setAttribute('aria-label',entry.title+' · '+(attention.level==='unknown'?'Estado de alertas sin confirmar':attention.count+' alertas por atender'));
      }
      const title=document.createElement('span');title.className='app-title';title.textContent=entry.title;
      const summary=document.createElement('span');summary.className='app-summary';summary.textContent=entry.summary+(entry.available===false?' · Aún no disponible para esta pareja.':entry.application_mode==='author'?' · Requiere a '+entry.author+': '+entry.dependency:entry.application_mode==='legacy-author'?' · Enlace al bot del autor.':'');
      const author=document.createElement('span');author.className='app-author';
      const name=document.createElement('span');name.textContent=entry.author;const arrow=document.createElement('span');arrow.textContent='↗';arrow.setAttribute('aria-hidden','true');author.append(name,arrow);
      link.append(icon,title,summary,author);
      const star=document.createElement('button');star.className='star';star.textContent=favorites.has(entry.id)?'★':'☆';star.setAttribute('aria-label','Favorita: '+entry.title);star.setAttribute('aria-pressed',String(favorites.has(entry.id)));
      star.onclick=()=>{if(favorites.has(entry.id))favorites.delete(entry.id);else favorites.add(entry.id);try{localStorage.setItem(storageKey,JSON.stringify([...favorites].slice(-256)));}catch{}render();};
      row.append(link,star);return row;
    }));
    paintAttention();
    byId('empty').hidden=shown.length>0;
    byId('empty').textContent=term?'No hay coincidencias. Probá otro nombre.':favoritesOnly?'Tocá ☆ en una app para guardarla acá.':'Todavía no hay aplicaciones publicadas.';
  }
  function matchesAttention(entry){
    if(!attention||entry.available===false)return false;
    if(entry.application_mode==='paired')return entry.capability==='sessions'&&Boolean(entry.receiver_bot)&&entry.receiver_bot===attention.bot_username;
    return attention.app_url?sameApp(entry.url,attention.app_url):/^sessions$/i.test(entry.title);
  }

  function sameApp(left,right){
    try{const a=new URL(left),b=new URL(right);return a.origin===b.origin&&a.pathname.toLowerCase()===b.pathname.toLowerCase();}catch{return false;}
  }
  function paintAttention(){
    const box=byId('alert-trail');box.replaceChildren();
    const entry=attention&&(entries.map(resolvedEntry).find(matchesAttention)||(safeURL({url:attention.app_url,launch:'web'})?{url:attention.app_url}:null));
    box.hidden=!entry||(!attention.count&&attention.level!=='unknown');
    if(box.hidden)return;
    const title=document.createElement('strong');
    title.textContent=attention.symbol+' '+(attention.level==='unknown'?'Estado de alertas sin confirmar':attention.count+' alerta'+(attention.count===1?'':'s')+' por atender');
    const list=document.createElement('ul');
    for(const row of attention.summaries){const item=document.createElement('li');item.textContent=row.symbol+' '+row.summary;list.append(item);}
    const link=document.createElement('a');link.href=entry.url;link.textContent='Ver alertas en Sessions ↗';
    link.onclick=event=>{if(new URL(entry.url).host==='t.me'&&webapp?.openTelegramLink){event.preventDefault();webapp.openTelegramLink(entry.url);}};
    box.append(title,list,link);
    if(attention.level==='unknown'){const note=document.createElement('p');note.textContent='No pudimos confirmar el estado actual. Abrí Sessions para comprobarlo.';box.append(note);}
  }
  async function loadAttention(){
    if(attentionPending||document.visibilityState==='hidden'||!webapp?.initData)return;
    attentionPending=true;
    const controller=new AbortController(),deadline=setTimeout(()=>controller.abort(),5000);
    try{
      const response=await fetch('/apps/attention',{method:'POST',credentials:'omit',redirect:'error',cache:'no-store',signal:controller.signal,
        headers:{'Content-Type':'application/json'},body:JSON.stringify({init_data:webapp.initData})});
      if(!response.ok)throw Error('unavailable');const value=await response.json();
      const symbols={clear:'',info:'🔵',warning:'🟠',error:'🔴',unknown:'⚪'};
      if(value.schema!=='telecodex.alert-attention/v1'||!(value.level in symbols)||value.symbol!==symbols[value.level]||
        !Number.isInteger(value.count)||value.count<0||value.count>100000||!Array.isArray(value.summaries)||value.summaries.length>3||
        !value.summaries.every(r=>r&&typeof r.summary==='string'&&r.summary.length<=280&&['🔴','🟠','🔵'].includes(r.symbol))||
        !safeURL({url:value.app_url,launch:'web'}))throw Error('invalid');
      attention=value;
    }catch{
      // Keep no private summaries after auth/route/observation expiry. Unknown is never green.
      attention={...attention,level:'unknown',symbol:'⚪',count:0,summaries:[]};
    }finally{clearTimeout(deadline);attentionPending=false;render();}
  }
  async function load(){
    if(pending)return;
    const request=new AbortController();pending=request;const deadline=setTimeout(()=>request.abort(),12000);
    byId('refresh').disabled=true;byId('notice').textContent='Cargando aplicaciones…';
    try{
      const response=await fetch('/apps/catalog.json',{credentials:'same-origin',redirect:'error',cache:'no-store',signal:request.signal});
      if(!response.ok)throw Error('unavailable');const value=await response.json();
      if(value.schema!=='dm.miniapp-navigation/v1'||!Array.isArray(value.apps)||value.apps.length>256)throw Error('invalid');
      const seen=new Set();entries=value.apps.filter(e=>e&&['id','title','summary','url','author'].every(k=>typeof e[k]==='string'&&e[k].length<4096)&&safeURL(e)&&!seen.has(e.id)&&seen.add(e.id));
      byId('notice').textContent=value.partial?'Algunas fuentes no respondieron. Podés volver a actualizar.':'';render();
    }catch{byId('notice').textContent='No pudimos actualizar las aplicaciones. Tocá ↻ para reintentar.';if(!entries.length)byId('empty').hidden=true;}
    finally{clearTimeout(deadline);pending=null;byId('refresh').disabled=false;}
  }
  // First-paint data is request-scoped HTML, never a persistent catalog cache.
  try{const value=JSON.parse(byId('initial-apps')?.textContent||'null');if(value?.schema==='dm.miniapp-navigation/v1'&&Array.isArray(value.apps)){
    entries=value.apps.filter(e=>e&&['id','title','summary','url','author'].every(k=>typeof e[k]==='string'&&e[k].length<4096)&&safeURL(e));render();
  }}catch{}
  byId('receiver-choice').addEventListener('change',()=>{receiverChoice=byId('receiver-choice').value;try{localStorage.setItem('dm.launcher.receiver/v1',receiverChoice);}catch{}render();});
  byId('search').addEventListener('input',render);
  byId('favorites').onclick=()=>{favoritesOnly=!favoritesOnly;byId('favorites').setAttribute('aria-pressed',String(favoritesOnly));render();};
  byId('refresh').onclick=()=>{load();loadAttention();};
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'){load();loadAttention();}});
  window.addEventListener('pageshow',load);
  function chrome(){const css=getComputedStyle(document.documentElement);try{webapp?.setHeaderColor(css.getPropertyValue('--dm-background').trim());webapp?.setBackgroundColor(css.getPropertyValue('--dm-background').trim());}catch{}}
  window.addEventListener('home-style:resolved',chrome);
  webapp?.ready?.();load();loadAttention();setInterval(loadAttention,30000);
})();
