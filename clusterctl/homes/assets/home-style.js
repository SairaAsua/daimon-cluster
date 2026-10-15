/* Foreground appearance reconciliation. Style data never authorizes access. */
"use strict";
(() => {
  const policy=document.documentElement.dataset?.stylePolicy;
  const authored=policy!==undefined?policy!=='inherit':document.documentElement.dataset?.styleSelection==='explicit';
  const channel=typeof BroadcastChannel==='function'?new BroadcastChannel('dm.home-style/v1'):null;
  if(authored){
    // An editor can notify other consumers while retaining its own interface.
    window.addEventListener('home-style:refresh',()=>channel?.postMessage('changed'));
    return;
  }
  // Independent apps consume a public author stylesheet. It blocks the first
  // paint in their head; later replacements apply only after a successful load.
  const sheet=document.querySelector('link[data-home-style]');
  if(sheet){
    const initial=sheet.href;let active=sheet,pending=null,timer;
    function cancel(){if(pending){clearTimeout(pending.deadline);pending.node.remove();pending=null;}}
    function refresh(){
      if(document.visibilityState!=='visible'||pending)return;
      const node=document.createElement('link'),url=new URL(initial);
      url.searchParams.set('refresh',String(Date.now()));node.rel='stylesheet';node.href=url.href;
      const request={node};request.deadline=setTimeout(()=>{if(pending===request)cancel();},10000);pending=request;
      node.onload=()=>{if(pending!==request)return;clearTimeout(request.deadline);pending=null;active.remove();active=node;window.dispatchEvent(new CustomEvent('home-style:resolved'));};
      node.onerror=()=>{if(pending===request)cancel();};document.head.append(node);
    }
    function foreground(){clearTimeout(timer);if(document.visibilityState!=='visible'){cancel();return;}refresh();timer=setTimeout(foreground,15000);}
    document.addEventListener('visibilitychange',foreground);
    window.addEventListener('pageshow',event=>{if(event.persisted)foreground();});
    window.addEventListener('pagehide',()=>{clearTimeout(timer);cancel();});
    window.addEventListener('home-style:refresh',refresh);
    timer=setTimeout(foreground,15000);
    return;
  }
  const names={background:['--space','--home-background','--dm-background'],surface:['--panel','--panel2','--home-surface','--dm-surface'],text:['--ink','--muted','--home-text','--dm-text'],accent:['--cyan','--amber','--mauve','--line','--home-accent','--dm-accent'],bodyFont:['--home-font','--dm-body-font'],headingFont:['--home-heading-font','--dm-heading-font'],radius:['--home-radius','--dm-radius'],gap:['--home-gap','--dm-gap']};
  let current=null, request=null, timer;
  const match=location.pathname.match(/^\/view\/([a-f0-9]{32})$/);
  const surface=match?match[1]:(document.documentElement.dataset?.styleSurface || 'home');
  const personal=document.documentElement.dataset?.styleViewer==='personal';
  const listeners=new Set();
  function publish(frame) { if(current) frame.contentWindow?.postMessage({type:'home-artifact:style',contract:'homemaker.appearance/v1',appearance:current.appearance}, '*'); }
  async function refresh() {
    if(request || document.visibilityState!=='visible') return;
    const controller=new AbortController();request=controller;
    const deadline=setTimeout(()=>{controller.abort();if(request===controller)request=null;},10000);
    try {
      const response=await fetch('/style.json?surface='+encodeURIComponent(surface)+(personal?'&viewer=personal':''),{credentials:'same-origin',redirect:'error',signal:controller.signal});
      if(!response.ok) return;
      const value=await response.json(), a=value.appearance;
      if(controller.signal.aborted || request!==controller || document.visibilityState!=='visible')return;
      if(value.contract!=='homemaker.resolved/v1') return;
      if(value.font_assets===true && !document.getElementById('homemaker-font-assets')) {
        const link=document.createElement('link');link.id='homemaker-font-assets';link.rel='stylesheet';link.href='/design-assets/styles/fonts.css';document.head.append(link);
      }
      if(a && (!['background','surface','text','accent'].every(k=>/^#[a-f0-9]{6}$/i.test(a[k])) || !['bodyFont','headingFont'].every(k=>typeof a[k]==='string' && a[k].length<128 && /^[A-Za-z0-9 ,\"'-]+$/.test(a[k])) || !['0px','12px'].includes(a.radius) || !['12px','24px'].includes(a.gap) || !['dark','light'].includes(a.scheme))) return;
      for(const [key,vars] of Object.entries(names)) for(const name of vars) {
        if(a) document.documentElement.style.setProperty(name,a[key]); else document.documentElement.style.removeProperty(name);
      }
      if(a) { document.documentElement.style.colorScheme=a.scheme; document.body.style.fontFamily=a.bodyFont; }
      else { document.documentElement.style.removeProperty('color-scheme');document.body.style.removeProperty('font-family'); }
      current=value;
      document.querySelectorAll('iframe.preview').forEach(frame=>{publish(frame);if(!listeners.has(frame)){frame.addEventListener('load',()=>publish(frame));listeners.add(frame);}});
      window.dispatchEvent(new CustomEvent('home-style:resolved',{detail:{mode:value.mode,design_ref:value.design_ref,design_revision:value.design_revision}}));
    } catch { /* Keep the last valid accessible presentation. */ }
    finally {clearTimeout(deadline);if(request===controller)request=null;}
  }
  function abortRequest() {request?.abort();request=null;}
  function foreground() {
    clearTimeout(timer);
    if(document.visibilityState!=='visible'){abortRequest();return;}
    refresh();
    timer=setTimeout(foreground,15000);
  }
  if(channel)channel.addEventListener('message',()=>refresh());
  window.addEventListener('pageshow',foreground);
  window.addEventListener('pagehide',()=>{clearTimeout(timer);abortRequest();});
  document.addEventListener('visibilitychange',foreground);
  window.addEventListener('home-style:refresh',()=>{refresh();channel?.postMessage('changed');});
  foreground();
})();
