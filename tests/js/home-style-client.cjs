const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),test=require('node:test');
const appearance={background:'#080b14',surface:'#080b14',text:'#eeeaf6',accent:'#ffcc99',bodyFont:'monospace',headingFont:'monospace',radius:'12px',gap:'24px',scheme:'dark'};
function fixture(selection='default',policy) {
 const listeners={},values={},style={setProperty:(k,v)=>values[k]=v,removeProperty:k=>delete values[k]};
 const parent={},window={parent,addEventListener:(event,fn)=>listeners[event]=fn};
 const ctx={window,parent,document:{documentElement:{dataset:{styleSelection:selection,stylePolicy:policy},style},body:{style}}};
 vm.createContext(ctx);vm.runInContext(fs.readFileSync('clusterctl/homes/assets/artifact-style.js','utf8'),ctx);
 return {listeners,values,parent};
}
test('actual parent sends validated appearance; siblings/null origin/unsafe CSS never alter style',()=>{
 const f=fixture();const data={type:'home-artifact:style',contract:'homemaker.appearance/v1',appearance};
 for(const event of [{source:{},origin:'https://home.example',data},{source:f.parent,origin:'null',data},{source:f.parent,origin:'https://home.example',data:{...data,appearance:{...appearance,bodyFont:'url(https://hostile)'}}}])f.listeners.message(event);
 assert.deepEqual(f.values,{});
 f.listeners.message({source:f.parent,origin:'https://home.example',data});assert.equal(f.values['--space'],appearance.background);assert.equal(f.values['--home-font'],'monospace');
 f.listeners.message({source:f.parent,origin:'https://home.example',data:{...data,appearance:null}});assert.deepEqual(f.values,{});
});
test('explicitly authored work never subscribes to default appearance',()=>{assert.equal(fixture('explicit').listeners.message,undefined);});
test('source-owned policies preserve authored work without disabling inheritance elsewhere',()=>{
 for(const policy of ['authored','unsupported',''])assert.equal(fixture('default',policy).listeners.message,undefined);
 assert.equal(typeof fixture('explicit','inherit').listeners.message,'function');
});
test('an authored editor broadcasts explicit saves without fetching or applying its own default',()=>{
 const events={},messages=[];
 const context={document:{documentElement:{dataset:{stylePolicy:'authored'}}},
  window:{addEventListener:(key,fn)=>events[key]=fn},
  BroadcastChannel:class{postMessage(value){messages.push(value);}},
  fetch:()=>{throw Error('authored editor fetched its default');},
  setTimeout:()=>{throw Error('authored editor installed a refresh timer');}};
 vm.createContext(context);vm.runInContext(fs.readFileSync('clusterctl/homes/assets/home-style.js','utf8'),context);
 events['home-style:refresh']();assert.deepEqual(messages,['changed']);
 assert.equal(events.pageshow,undefined);
});
test('a stalled refresh times out and resumes; a hidden/closed page cannot apply a stale response',async()=>{
 const events={},timers=[],fetches=[],styleValues={};
 const document={visibilityState:'visible',documentElement:{style:{setProperty:(k,v)=>styleValues[k]=v,removeProperty:k=>delete styleValues[k]}},body:{style:{}},querySelector:()=>null,querySelectorAll:()=>[],addEventListener:(key,fn)=>events[key]=fn};
 const context={document,window:{addEventListener:(key,fn)=>events[key]=fn,dispatchEvent:()=>{}},location:{pathname:'/'},AbortController,
  setTimeout:(fn,delay)=>{timers.push({fn,delay});return timers.length;},clearTimeout:()=>{},CustomEvent:class{},
  fetch:(_url,options)=>new Promise(resolve=>fetches.push({resolve,signal:options.signal}))};
 vm.createContext(context);vm.runInContext(fs.readFileSync('clusterctl/homes/assets/home-style.js','utf8'),context);
 assert.equal(fetches.length,1);
 timers.find(t=>t.delay===10000).fn();assert.equal(fetches[0].signal.aborted,true);
 events['home-style:refresh']();assert.equal(fetches.length,2);
 document.visibilityState='hidden';events.visibilitychange();assert.equal(fetches[1].signal.aborted,true);
 fetches[1].resolve({ok:true,json:async()=>({contract:'homemaker.resolved/v1',appearance})});
 await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(styleValues,{});
 document.visibilityState='visible';events.visibilitychange();assert.equal(fetches.length,3);
 fetches[2].resolve({ok:true,json:async()=>({contract:'homemaker.resolved/v1',appearance})});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(styleValues['--space'],appearance.background);
 events.pagehide();assert.equal(fetches[2].signal.aborted,false);
});

test('public stylesheet replacement retains last valid CSS on timeout, hidden state and late errors',()=>{
 const events={},timers=[],nodes=[],removed=[];
 const original={href:'https://home.example/style.css?surface=sessions',remove:()=>removed.push('original')};
 const document={visibilityState:'visible',documentElement:{dataset:{}},querySelector:()=>original,
   createElement:()=>{const n={remove:()=>removed.push(n)};nodes.push(n);return n;},
   head:{append:()=>{}},addEventListener:(k,f)=>events[k]=f};
 const context={document,window:{addEventListener:(k,f)=>events[k]=f,dispatchEvent:()=>{}},URL,Date,CustomEvent:class{},
   setTimeout:(f,ms)=>{timers.push({f,ms});return timers.length;},clearTimeout:()=>{}};
 vm.createContext(context);vm.runInContext(fs.readFileSync('clusterctl/homes/assets/home-style.js','utf8'),context);
 assert.equal(nodes.length,0);events.pageshow({persisted:false});assert.equal(nodes.length,0);
 events['home-style:refresh']();const failed=nodes[0];failed.onerror();assert.ok(!removed.includes('original'));
 events['home-style:refresh']();const next=nodes[1];failed.onerror();next.onload();assert.ok(removed.includes('original'));
 events['home-style:refresh']();const hidden=nodes[2];document.visibilityState='hidden';events.visibilitychange();
 hidden.onload();assert.ok(removed.includes(hidden));assert.ok(!removed.includes(next));
});
