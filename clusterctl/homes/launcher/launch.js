/* Same-origin navigation only. The receiving app still verifies identity/grants. */
"use strict";
async function routeMiniApp(config, env) {
  env ||= {location, get storage(){return sessionStorage;}, webapp:window.Telegram?.WebApp, crypto, now:Date.now()};
  const raw=env.webapp?.initData;
  if(!raw)return false;
  // Do not route an ordinary reopening from an older SDK cache.
  if(new URLSearchParams((env.location.hash||'').slice(1)).get('tgWebAppData')!==raw)return false;
  const selector=new URLSearchParams(raw).get('start_param');
  if(!selector)return false;
  const route=config?.schema==='dm.miniapp-routes/v1' && config.origins?.[env.location.origin]?.find(r=>selector.startsWith(r.prefix));
  if(!route)return false;
  if(!/^[A-Za-z0-9_-]{1,512}$/.test(selector)||!/^\/[A-Za-z0-9_-]+\/$/.test(route.path)||route.path==='/apps/')throw Error('Invalid app route');
  // Telegram's SDK already retains initialization parameters in this tab. Bind
  // one brief transition to its exact current payload without copying it into
  // a URL, custom payload store, public catalog or server log.
  const params=JSON.parse(env.storage.getItem('__telegram__initParams')||'null');
  if(raw.length>16384||params?.tgWebAppData!==raw)throw Error('Fresh launch cache unavailable');
  const bytes=await env.crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
  const fingerprint=Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
  env.storage.setItem('dm.miniapp-handoff/v1',JSON.stringify({schema:'dm.miniapp-handoff/v1',path:route.path,created_at:env.now,fingerprint}));
  // No query/hash carry is allowed. The destination consumes the exact cache
  // once and its usual signature check authorizes the signed selector.
  env.location.replace(route.path);
  return true;
}
if(typeof module!=='undefined')module.exports=routeMiniApp;
else window.DaimonMiniAppLaunch=routeMiniApp;
