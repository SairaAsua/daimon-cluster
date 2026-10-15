/* Catalog metadata is text and navigation, never executable code or authority. */
"use strict";
(() => {
  const byId=id=>document.getElementById(id), webapp=window.Telegram?.WebApp;
  const storageKey='dm.launcher.favorites/v1';
  let entries=[], favorites=new Set(), favoritesOnly=false, pending=null;
  try{const saved=JSON.parse(localStorage.getItem(storageKey)||'[]');if(Array.isArray(saved))favorites=new Set(saved.filter(x=>typeof x==='string').slice(0,256));}catch{}
  const icons={
    nexus:'<circle cx="16" cy="16" r="5"/><ellipse cx="16" cy="16" rx="14" ry="6" transform="rotate(-40 16 16)"/><path d="M16 1v5m0 20v5M1 16h5m20 0h5"/>',
    sessions:'<rect x="3" y="4" width="26" height="24" rx="4"/><path d="M3 11h26M8 8h1m3 0h1M7 20h4l3-5 4 9 3-6h4"/>',
    homemaker:'<path d="m2 15 14-12 14 12M6 12v17h20V12M12 29V18h8v11"/><circle cx="23" cy="7" r="3"/>',
    app:'<rect x="3" y="3" width="10" height="10" rx="3"/><rect x="19" y="3" width="10" height="10" rx="3"/><rect x="3" y="19" width="10" height="10" rx="3"/><path d="M19 24h10m-5-5v10"/>'};
  // Web targets are qualified by the gateway's configured owner application,
  // not promoted from arbitrary published links. Never execute URL schemes.
  function safeURL(entry){try{const u=new URL(entry.url);return u.protocol==='https:'&&(u.host==='t.me'||entry.launch==='web')&&!u.username&&!u.password&&!u.hash?u:null;}catch{return null;}}
  function render(){
    const term=byId('search').value.toLocaleLowerCase();
    const shown=entries.filter(e=>(!favoritesOnly||favorites.has(e.id))&&[e.title,e.summary,e.author].join(' ').toLocaleLowerCase().includes(term));
    byId('count').textContent=shown.length+' / '+entries.length;
    byId('apps').replaceChildren(...shown.map(entry=>{
      const row=document.createElement('li');row.className='app';
      const link=document.createElement('a');link.className='app-link';link.href=entry.url;
      link.addEventListener('click',event=>{if(new URL(entry.url).host==='t.me'&&webapp?.openTelegramLink){event.preventDefault();webapp.openTelegramLink(entry.url);}});
      const icon=document.createElement('span');icon.className='app-icon';icon.setAttribute('aria-hidden','true');
      const key=/nexus/i.test(entry.title)?'nexus':/sessions/i.test(entry.title)?'sessions':/home\s*maker/i.test(entry.title)?'homemaker':'app';
      icon.innerHTML='<svg viewBox="0 0 32 32">'+icons[key]+'</svg>';
      const title=document.createElement('span');title.className='app-title';title.textContent=entry.title;
      const summary=document.createElement('span');summary.className='app-summary';summary.textContent=entry.summary;
      const author=document.createElement('span');author.className='app-author';
      const name=document.createElement('span');name.textContent=entry.author;const arrow=document.createElement('span');arrow.textContent='↗';arrow.setAttribute('aria-hidden','true');author.append(name,arrow);
      link.append(icon,title,summary,author);
      const star=document.createElement('button');star.className='star';star.textContent=favorites.has(entry.id)?'★':'☆';star.setAttribute('aria-label','Favorita: '+entry.title);star.setAttribute('aria-pressed',String(favorites.has(entry.id)));
      star.onclick=()=>{if(favorites.has(entry.id))favorites.delete(entry.id);else favorites.add(entry.id);try{localStorage.setItem(storageKey,JSON.stringify([...favorites].slice(-256)));}catch{}render();};
      row.append(link,star);return row;
    }));
    byId('empty').hidden=shown.length>0;
    byId('empty').textContent=term?'No hay coincidencias. Probá otro nombre.':favoritesOnly?'Tocá ☆ en una app para guardarla acá.':'Todavía no hay aplicaciones publicadas.';
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
  byId('search').addEventListener('input',render);
  byId('favorites').onclick=()=>{favoritesOnly=!favoritesOnly;byId('favorites').setAttribute('aria-pressed',String(favoritesOnly));render();};
  byId('refresh').onclick=load;
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')load();});
  window.addEventListener('pageshow',load);
  function chrome(){const css=getComputedStyle(document.documentElement);try{webapp?.setHeaderColor(css.getPropertyValue('--dm-background').trim());webapp?.setBackgroundColor(css.getPropertyValue('--dm-background').trim());}catch{}}
  window.addEventListener('home-style:resolved',chrome);
  webapp?.ready?.();load();
})();
