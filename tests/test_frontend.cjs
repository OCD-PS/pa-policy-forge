/* Shared browser-event regressions. Run with: node --test tests/test_frontend.cjs
 * Requires jsdom on NODE_PATH (kept outside production dependencies).
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { JSDOM } = require('jsdom');
const source = fs.readFileSync(path.join(__dirname, '..', 'app', 'static', 'app.js'), 'utf8');
const styles = fs.readFileSync(path.join(__dirname, '..', 'app', 'static', 'app.css'), 'utf8');

async function page(markup) {
  const dom = new JSDOM(markup, {url: 'https://forge.test/', runScripts: 'outside-only', pretendToBeVisual:true});
  await new Promise(resolve => dom.window.addEventListener('load', resolve, {once: true}));
  const errors = [];
  dom.window.console.error = (...args) => errors.push(args.join(' '));
  dom.window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  dom.window.HTMLDialogElement.prototype.close = function () { this.open = false; };
  dom.window.eval(source);
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  return {dom, window: dom.window, document: dom.window.document, errors};
}

test('inactive SCM scope never blocks standalone or Panorama target creation', async () => {
  const {dom, document, window, errors} = await page(`<form>
    <select data-target-select><option>panos</option><option>panorama</option><option>scm</option></select>
    <div data-targets="panos panorama"><input name="endpoint" required value="https://firewall.test"></div>
    <div data-targets="scm" hidden>
      <select data-scm-scope-select><option>folder</option><option>snippet</option></select>
      <div data-scm-scope="folder"><input name="folder" required></div>
      <div data-scm-scope="snippet" hidden><input name="snippet" required></div>
    </div></form>`);
  const form = document.querySelector('form');
  const target = document.querySelector('[data-target-select]');
  assert.equal(form.checkValidity(), true, 'hidden SCM folder must be disabled');
  target.value = 'panorama'; target.dispatchEvent(new window.Event('change'));
  assert.equal(form.checkValidity(), true);
  target.value = 'scm'; target.dispatchEvent(new window.Event('change'));
  assert.equal(document.querySelector('[name=folder]').disabled, false);
  assert.equal(document.querySelector('[name=snippet]').disabled, true);
  assert.equal(form.checkValidity(), false, 'active required SCM scope still validates');
  assert.deepEqual(errors, []); dom.window.close();
});

test('filtered policy range selection never includes hidden policies', async () => {
  const {dom, document, window, errors} = await page(`<input data-policy-expression><span data-policy-filter-status></span>
    <table><tbody>${['keep-first', 'hidden-middle', 'keep-last'].map(name => `<tr data-policy-row data-name="${name}"><td><input type="checkbox" data-policy-select></td><td>${name}</td></tr>`).join('')}</tbody></table>
    <span data-policy-action-count></span>`);
  const filter = document.querySelector('[data-policy-expression]');
  filter.value = "name contains 'keep'"; filter.dispatchEvent(new window.Event('input'));
  const checks = [...document.querySelectorAll('[data-policy-select]')];
  checks[0].click();
  checks[2].dispatchEvent(new window.MouseEvent('click', {bubbles:true, shiftKey:true}));
  assert.deepEqual(checks.map(check => check.checked), [true, false, true]);
  assert.deepEqual(errors, []); dom.window.close();
});

function configMarkup() {
  const record = (name, family) => JSON.stringify({name, ui_family:family, is_entry:true, kind:family, owner:'vsys1', locator:name, edit_fields:[]});
  return `<div class="config-record-list"><div class="policy-filterbar"><input data-table-filter="#config"></div>
    <form><table id="config"><tbody>${[['port-red','Ethernet'],['port-blue','VLAN']].map(([name,family]) => `<tr data-config-record-row data-config-record='${record(name,family)}'><td><input type="checkbox" data-config-record-select></td><td><button type="button" data-config-record-edit>${name}</button></td></tr>`).join('')}</tbody></table><div class="object-actionbar"><span data-config-selected-count></span><button data-config-delete disabled>Delete</button></div></form></div>
    <dialog data-config-dialog data-config-create-url="/config-workspaces/1/configuration/create-basic"><form data-config-form action="/config-workspaces/1/configuration/preview"><input data-config-locator><input data-config-updates><div class="card-header"><div><h2 data-config-dialog-title></h2><span data-config-dialog-kind></span><span data-config-dialog-owner></span></div></div><div data-config-field-tabs></div><div data-config-fields></div><div class="bulk-dialog-actions"><button class="btn-primary" name="operation">Save</button></div></form></dialog>`;
}

test('configuration family and text filters compose instead of resetting each other', async () => {
  const {dom, document, window, errors} = await page(configMarkup());
  const rows = [...document.querySelectorAll('[data-config-record-row]')];
  const filter = document.querySelector('[data-table-filter]');
  filter.value = 'blue'; filter.dispatchEvent(new window.Event('input'));
  assert.deepEqual(rows.map(row => row.hidden), [true, true], 'Ethernet family remains active');
  [...document.querySelectorAll('.config-family-tabs button')].find(button => button.textContent === 'VLAN').click();
  assert.deepEqual(rows.map(row => row.hidden), [true, false]);
  filter.value = ''; filter.dispatchEvent(new window.Event('input'));
  assert.deepEqual(rows.map(row => row.hidden), [true, false], 'clearing search retains family');
  assert.deepEqual(errors, []); dom.window.close();
});

test('closed details are opened when an in-page action links to their contents', async () => {
  const {dom, document, errors} = await page('<a href="#mapping">Behandelen</a><details id="mapping"><summary>Mapping</summary><p>Editor</p></details>');
  document.querySelector('a').click();
  assert.equal(document.querySelector('details').open, true);
  assert.deepEqual(errors, []); dom.window.close();
});

test('hidden editor fields remain hidden despite layout display rules', async () => {
  const {dom, document, window} = await page(`<style>${styles}</style><div class="field full" data-dynamic-filter hidden>Dynamic filter</div>`);
  assert.equal(window.getComputedStyle(document.querySelector('[data-dynamic-filter]')).display, 'none');
  dom.window.close();
});

test('offline policy picker rows support multiple selections like object groups', async () => {
  const {dom, document, errors} = await page(`<dialog data-offline-policy-dialog><form action="/config-workspaces/1/policies/preview">
    <div data-offline-policy-field="source"><input data-offline-policy-input value=""><div data-offline-policy-values></div><input readonly data-offline-policy-entry data-offline-policy-kinds="addresses"><button type="button" data-offline-policy-add>+</button></div>
    </form><div data-offline-policy-picker hidden><input data-offline-policy-picker-filter><span data-policy-picker-selected-count></span><div data-offline-policy-picker-results></div><button data-policy-picker-add-selected>Add selected</button><button data-offline-policy-picker-close>Close</button></div></dialog>
    <script type="application/json" data-offline-policy-catalog>[{"name":"one","kind":"addresses"},{"name":"two","kind":"addresses"}]</script>`);
  document.querySelector('[data-offline-policy-entry]').focus();
  document.querySelectorAll('.member-result')[0].click();
  document.querySelectorAll('.member-result')[1].click();
  assert.equal(document.querySelector('[data-policy-picker-selected-count]').textContent, '2');
  document.querySelector('[data-policy-picker-add-selected]').click();
  assert.equal(document.querySelector('[data-offline-policy-input]').value, 'one,two');
  assert.deepEqual(errors, []); dom.window.close();
});

function createSchemas() {
  return `<script type="application/json" data-config-create-templates>${JSON.stringify([
    {create_variant:'vlan', kind:'VLAN', label:'VLAN', owner:'vsys1', is_entry:true, edit_fields:[{path:'virtual-interface',label:'Virtual interface',kind:'text',value:''}]},
    {create_variant:'router', kind:'Virtual Router', label:'Virtual Router', owner:'vsys1', is_entry:true, edit_fields:[]},
  ])}</script>`;
}

test('empty configuration pages create through a real schema in the shared modal', async () => {
  const markup = configMarkup().replace(/<tbody>[\s\S]*?<\/tbody>/, '<tbody></tbody>') + createSchemas();
  const {dom, document, window, errors} = await page(markup);
  const add = document.querySelector('[data-config-add]');
  assert.ok(add, 'Empty page must expose Add without requiring a seed row');
  assert.equal(document.querySelector('.object-actionbar').hidden, false);
  add.click();
  const form = document.querySelector('[data-config-form]');
  assert.equal(document.querySelector('[data-config-dialog]').open, true);
  assert.equal(form.getAttribute('action'), '/config-workspaces/1/configuration/create-basic');
  assert.equal(form.querySelector('[name=variant]').value, 'vlan');
  form.querySelector('[name=name]').value = 'VLAN-10';
  document.querySelector('[data-config-fields] input:not([name])').value = 'vlan.10';
  form.dispatchEvent(new window.Event('submit', {cancelable:true}));
  assert.deepEqual(JSON.parse(form.querySelector('[data-config-updates]').value), [{path:'virtual-interface',kind:'text',value:'vlan.10'}]);
  document.querySelector('[data-config-create-variant]').value = '1';
  add.click();
  assert.equal(form.querySelector('[name=variant]').value, 'router');
  assert.equal(form.querySelector('[name=name]').value, '');
  assert.deepEqual(errors, []); dom.window.close();
});

test('editing after Add restores the update endpoint and clears create variant', async () => {
  const {dom, document, errors} = await page(configMarkup() + createSchemas());
  document.querySelector('[data-config-add]').click();
  document.querySelector('[data-config-record-edit]').click();
  const form = document.querySelector('[data-config-form]');
  assert.equal(form.getAttribute('action'), '/config-workspaces/1/configuration/preview');
  assert.equal(form.querySelector('[name=variant]').value, '');
  assert.deepEqual(errors, []); dom.window.close();
});

test('generic Add preserves zero, honors field limits and never submits protected fields', async () => {
  const schema = {create_variant:'router', kind:'Virtual Router', owner:'vsys1', is_entry:true, edit_fields:[
    {path:'metric',label:'Metric',kind:'text',value:0,required:true,max_length:7},
    {path:'secret',label:'Existing protected value',kind:'protected',value:'must-not-be-rendered'},
  ]};
  const {dom, document, window, errors} = await page(configMarkup() + `<script type="application/json" data-config-create-templates>${JSON.stringify([schema])}</script>`);
  document.querySelector('[data-config-add]').click();
  const form = document.querySelector('[data-config-form]');
  const metric = document.querySelector('[data-config-fields] input:not([name])');
  assert.equal(metric.value, '0');
  assert.equal(metric.required, true);
  assert.equal(metric.maxLength, 7);
  assert.equal(form.querySelector('[name=name]').required, true);
  assert.equal(form.querySelector('[name=name]').maxLength, 127);
  assert.equal(document.querySelector('[data-config-fields]').textContent.includes('must-not-be-rendered'), false);
  form.dispatchEvent(new window.Event('submit', {cancelable:true}));
  assert.deepEqual(JSON.parse(form.querySelector('[data-config-updates]').value), []);
  assert.deepEqual(errors, []); dom.window.close();
});

test('optional absent boolean fields stay unset until deliberately selected', async () => {
  const schema = {create_variant:'zone', kind:'Zone', owner:'vsys1', is_entry:true, edit_fields:[
    {path:'enable-user-identification',label:'User Identification',kind:'boolean',value:'',optional:true},
    {path:'logging',label:'Logging',kind:'bool',value:'',optional:true},
    {path:'mode',label:'Mode',kind:'text',value:'',optional:true,options:['','layer3','layer2']},
  ]};
  const {dom, document, window, errors} = await page(configMarkup() + `<script type="application/json" data-config-create-templates>${JSON.stringify([schema])}</script>`);
  document.querySelector('[data-config-add]').click();
  const form = document.querySelector('[data-config-form]');
  const selects = [...document.querySelectorAll('[data-config-fields] select')];
  assert.deepEqual(selects.map(select => select.value), ['', '', '']);
  assert.ok(selects.every(select => select.selectedOptions[0].textContent === 'Niet ingesteld'));
  form.dispatchEvent(new window.Event('submit', {cancelable:true}));
  assert.deepEqual(JSON.parse(form.querySelector('[data-config-updates]').value), []);
  selects[0].value = 'no';
  form.dispatchEvent(new window.Event('submit', {cancelable:true}));
  assert.deepEqual(JSON.parse(form.querySelector('[data-config-updates]').value), [{path:'enable-user-identification',kind:'boolean',value:'no'}]);
  assert.deepEqual(errors, []); dom.window.close();
});
