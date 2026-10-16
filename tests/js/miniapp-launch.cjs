const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto').webcrypto;
const launch=require('../../clusterctl/homes/launcher/launch.js');
const config={schema:'dm.miniapp-routes/v1',origins:{'https://apps.example':[{prefix:'nexus-',path:'/nexus/'}]}};
function env(raw='start_param=nexus-selected&signature=unverified-fixture'){
 const values=new Map([['__telegram__initParams',JSON.stringify({tgWebAppData:raw,tgWebAppPlatform:'android'})]]),navigated=[];
 return {location:{origin:'https://apps.example',hash:'#'+new URLSearchParams({tgWebAppData:raw}),replace:path=>navigated.push(path)},storage:{getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v)},webapp:{initData:raw},crypto,now:100000,values,navigated};
}
test('registered main-app selector routes without putting initialization in its URL',async()=>{
 const input=env();assert.equal(await launch(config,input),true);assert.deepEqual(input.navigated,['/nexus/']);
 const marker=JSON.parse(input.values.get('dm.miniapp-handoff/v1'));assert.equal(marker.path,'/nexus/');assert.match(marker.fingerprint,/^[a-f0-9]{64}$/);assert.equal(JSON.stringify(marker).includes('signature'),false);
});
test('ordinary Apps, foreign origins and unknown selectors retain launcher',async()=>{
 for(const input of [env('signature=fixture'),env('start_param=other-selected')]){assert.equal(await launch(config,input),false);assert.deepEqual(input.navigated,[]);}
 const foreign=env();foreign.location.origin='https://other.example';assert.equal(await launch(config,foreign),false);
 const reopened=env();reopened.location.hash='';assert.equal(await launch(config,reopened),false);
});
test('mismatched cache and blocked storage cannot silently lose identity',async()=>{
 const stale=env();stale.values.set('__telegram__initParams',JSON.stringify({tgWebAppData:'stale'}));await assert.rejects(launch(config,stale));assert.deepEqual(stale.navigated,[]);
 const denied=env();denied.storage.setItem=()=>{throw Error('Storage denied');};await assert.rejects(launch(config,denied));assert.deepEqual(denied.navigated,[]);
});
