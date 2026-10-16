'use strict';
// Actual agenda assets -> disposable HTTPS gateway -> official Vikunja.
// JSDOM exercises DOM/events, not rendering, WebViews or Google consent.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const https = require('node:https');
const fs = require('node:fs');
const {JSDOM, CookieJar, VirtualConsole} = require(process.env.AGENDA_JSDOM);
const origin = process.env.AGENDA_PREVIEW_ORIGIN;
assert.match(origin, /^https:\/\/127\.0\.0\.1:\d+$/);
const cookies = new CookieJar();
const passed = [];
let dropNextCommand = false;
let currentUI;

async function wire(path, options = {}) {
  const url = new URL(path, origin);
  assert.equal(url.origin, origin, 'Only the isolated fixture origin may receive requests');
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      // The disposable loopback fixture generates its own one-day certificate.
      rejectUnauthorized: false, agent: false, method: options.method || 'GET',
      headers: {Cookie: cookies.getCookieStringSync(origin), Origin: origin, ...options.headers},
      signal: options.signal,
    }, response => {
      for (const cookie of response.headers['set-cookie'] || []) cookies.setCookieSync(cookie, origin);
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => body += chunk);
      response.on('end', () => resolve({status: response.statusCode,
        ok: response.statusCode >= 200 && response.statusCode < 300,
        text: async () => body, json: async () => JSON.parse(body)}));
    });
    request.on('error', reject);
    request.end(options.body);
  });
}

async function until(predicate, label) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Timed out: ' + label);
}

async function load() {
  const html = await (await wire('/agenda/')).text();
  assert.ok(html.includes('Prueba local'));
  const errors = [];
  const console = new VirtualConsole();
  console.on('jsdomError', e => errors.push(e.message));
  const dom = new JSDOM(html, {url: origin+'/agenda/', runScripts:'outside-only',
    pretendToBeVisual:true, cookieJar:cookies, virtualConsole:console});
  const w = dom.window;
  const OriginalDate = w.Date;
  w.Date = class extends OriginalDate {
    constructor(...args) {super(...(args.length ? args : ['2026-11-01T18:00:00Z']));}
    static now() {return new OriginalDate('2026-11-01T18:00:00Z').getTime();}
  };
  w.crypto.randomUUID = crypto.randomUUID;
  w.confirm = () => true;
  w.AbortController = AbortController;
  w.HTMLDialogElement.prototype.showModal = function () {this.setAttribute('open','');};
  w.HTMLDialogElement.prototype.close = function () {this.removeAttribute('open');};
  w.fetch = async (url, options) => {
    const result = await wire(url, options);
    if (dropNextCommand && url.endsWith('/command')) {
      dropNextCommand = false;
      throw new Error('Fixture: acknowledgment lost after the saved write');
    }
    return result;
  };
  w.eval(await (await wire('/agenda/agenda.js')).text());
  const $ = id => w.document.getElementById(id);
  await until(() => !$('status').textContent.includes('Abriendo'), 'initial state');
  return {dom, w, $, errors};
}

function input(ui, form, name, value) {
  const element = ui.$(form).elements[name];
  element.value = value;
  element.dispatchEvent(new ui.w.Event('input', {bubbles:true}));
}
function submit(ui, form) {ui.$(form).dispatchEvent(new ui.w.Event('submit', {bubbles:true,cancelable:true}));}
function taskButton(ui, title) {
  return [...ui.w.document.querySelectorAll('.task-open')].find(b => b.textContent.includes(title));
}
async function state() {return (await wire('/agenda/api/state')).json();}
async function command(action, payload) {
  const result = await wire('/agenda/api/command', {method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action,payload:{...payload,operation_id:crypto.randomUUID()}})});
  assert.equal(result.status, 200);
  return result.json();
}
function passedStep(name) {passed.push(name);console.log('PASS '+name);}

(async () => {
  let ui = currentUI = await load();
  const initialOrigin = ui.w.location.origin;
  assert.equal(ui.$('initialize').hidden, false);
  ui.$('initialize-button').click();
  await until(() => ui.$('calendar-dialog').open, 'per-agenda first-use setup');
  assert.equal(ui.$('calendar-connect').textContent, 'Guardar cuenta preferida');
  ui.$('calendar-later').click();
  await until(() => !ui.$('calendar-dialog').open, 'continue without Google');
  assert.equal((await state()).calendar.connected, false);
  passedStep('Activate the private fixture agenda and skip unavailable Google consent');

  ui.$('new-project').click();
  input(ui, 'project-form', 'title', 'Obra de prueba');
  submit(ui, 'project-form');
  await until(() => !ui.$('project-dialog').open, 'create project');
  const project = (await state()).projects.find(p => p.title === 'Obra de prueba');
  assert.ok(project);
  ui.$('new-task').click();
  input(ui, 'task-form', 'project_id', String(project.id));
  input(ui, 'task-form', 'title', 'Llamar al ingeniero');
  input(ui, 'task-form', 'description', 'Continuar los trámites.');
  input(ui, 'task-form', 'date', '2026-11-01');
  submit(ui, 'task-form');
  await until(() => !ui.$('task-dialog').open, 'save date-only task');
  let task = (await state()).tasks[0];
  assert.equal(task.due_date, '2026-11-01T00:00:00Z');
  assert.ok(task.start_date.startsWith('0001-'));
  assert.ok(taskButton(ui, 'Llamar al ingeniero'));
  assert.match(ui.$('status').textContent, /guardada/);
  passedStep('Create a project and a November 1 task without inventing a time');

  taskButton(ui, 'Llamar al ingeniero').click();
  await until(() => !ui.$('observations').textContent.includes('Leyendo'), 'read observations');
  const googleDraft = new URL(ui.$('google-event').href);
  assert.equal(googleDraft.searchParams.get('dates'), '20261101/20261102');
  input(ui, 'observation-form', 'text', 'Primera observación de prueba.');
  submit(ui, 'observation-form');
  await until(() => ui.$('observations').textContent.includes('Primera observación'), 'save observation');
  assert.match(ui.$('observations').textContent, /Persona de prueba/);
  ui.$('complete-task').click();
  await until(() => ui.$('complete-task').textContent === 'Reabrir tarea', 'complete after a comment');
  assert.equal((await state()).tasks[0].done, true);
  ui.$('complete-task').click();
  await until(() => ui.$('complete-task').textContent === 'Marcar terminada', 'reopen');
  assert.equal((await state()).tasks[0].done, false);
  passedStep('Keep attributed observations and complete/reopen the same saved task');

  ui.$('edit-task').click();
  input(ui, 'task-form', 'time', '10:30');
  input(ui, 'task-form', 'duration', '45');
  input(ui, 'task-form', 'description', 'Un dato <seguro>\nSegundo renglón');
  submit(ui, 'task-form');
  await until(() => !ui.$('task-dialog').open, 'edit scheduled time');
  task = (await state()).tasks[0];
  assert.equal(task.start_date, '2026-11-01T16:30:00Z');
  assert.equal(task.end_date, '2026-11-01T17:15:00Z');
  assert.equal(task.description, 'Un dato <seguro>\nSegundo renglón');
  assert.equal((await state()).tasks.length, 1);
  passedStep('Edit date/time with the device timezone and preserve literal observation text');

  ui.$('calendar-settings').click();
  input(ui, 'calendar-form', 'email', 'persona@example.invalid');
  submit(ui, 'calendar-form');
  await until(() => !ui.$('calendar-dialog').open, 'save the preferred account');
  assert.equal((await state()).calendar.email, 'persona@example.invalid');
  assert.equal((await state()).calendar.connected, false);
  assert.match(ui.$('calendar-state').textContent, /pendiente/);
  passedStep('Save a preferred Google account while keeping consent explicitly pending');

  ui.$('new-task').click();
  input(ui, 'task-form', 'title', 'Guardado con respuesta perdida');
  dropNextCommand = true;
  submit(ui, 'task-form');
  await until(() => ui.$('task-error').textContent.includes('Conservamos lo escrito'), 'lost reply');
  assert.equal(ui.$('task-dialog').open, true);
  assert.equal(ui.$('task-form').elements.title.value, 'Guardado con respuesta perdida');
  assert.equal((await state()).tasks.filter(t => t.title === 'Guardado con respuesta perdida').length, 1);
  submit(ui, 'task-form');
  await until(() => !ui.$('task-dialog').open, 'exact retry');
  assert.equal((await state()).tasks.filter(t => t.title === 'Guardado con respuesta perdida').length, 1);
  passedStep('Retain the form after a lost acknowledgment and retry without creating a duplicate');

  ui.dom.window.close();
  ui = currentUI = await load();
  assert.equal(ui.w.location.origin, initialOrigin);
  assert.equal(ui.$('workspace').hidden, false);
  assert.equal(ui.$('calendar-dialog').open, false);
  ui.w.document.querySelector('[data-view=pending]').click();
  assert.ok(taskButton(ui, 'Llamar al ingeniero'));
  assert.ok(taskButton(ui, 'Guardado con respuesta perdida'));
  ui.$('search').value = 'ingeniero';
  ui.$('search').dispatchEvent(new ui.w.Event('input', {bubbles:true}));
  assert.equal(ui.w.document.querySelectorAll('.task-row').length, 1);
  ui.$('search').value = '';
  ui.$('search').dispatchEvent(new ui.w.Event('input', {bubbles:true}));
  passedStep('Reopen the app, restore canonical records and search without losing state');

  await command('task-create', {title:'Horario de otro cuerpo',project_id:project.id,
    date:'2026-11-02',time:'01:00',timezone:'Asia/Tokyo',duration:30});
  ui.$('refresh').click();
  await until(() => taskButton(ui, 'Horario de otro cuerpo'), 'refresh a task entered in another timezone');
  ui.w.document.querySelector('[data-view=today]').click();
  assert.ok(taskButton(ui, 'Horario de otro cuerpo'), 'Today must match the local date shown for a timed task');
  passedStep('Show a timed task on the viewer’s local day across body timezones');

  if (process.env.AGENDA_SNAPSHOT) {
    const css = await (await wire('/agenda/agenda.css')).text();
    const doc = ui.w.document.cloneNode(true);
    doc.querySelectorAll('script,link,dialog').forEach(e => e.remove());
    const style = doc.createElement('style');style.textContent=css;doc.head.append(style);
    doc.querySelector('.rehearsal').textContent = 'Vista previa de diseño · datos de ejemplo. Esta copia es de lectura; los controles están desactivados.';
    doc.querySelectorAll('button,input,select,textarea').forEach(e=>e.disabled=true);
    doc.querySelectorAll('a').forEach(e=>e.removeAttribute('href'));
    fs.writeFileSync(process.env.AGENDA_SNAPSHOT, domHTML(doc));
  }
  ui.w.fetch = async () => ({ok:false,status:403,json:async()=>({error:'agenda_access_denied'})});
  ui.$('refresh').disabled=false;ui.$('refresh').click();
  await until(() => ui.$('workspace').hidden, 'clear private data on access loss');
  assert.equal(ui.$('task-list').children.length, 0);
  assert.equal(ui.$('observations').children.length, 0);
  assert.match(ui.$('status').textContent, /Vuelve a entrar/);
  assert.deepEqual(ui.errors, []);
  passedStep('Clear the private view when the current session loses access');
  ui.dom.window.close();
  console.log(JSON.stringify({result:'passed',boundary:'DOM + actual HTTPS adapter + official Vikunja; not visual/Telegram/Google',checks:passed},null,2));
})().catch(error => {console.error(error.stack);process.exitCode=1;})
  .finally(() => {currentUI?.dom.window.close();https.globalAgent.destroy();});

function domHTML(document) {return '<!doctype html>\n'+document.documentElement.outerHTML;}
