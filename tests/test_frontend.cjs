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

async function page(markup, options = {}) {
  const dom = new JSDOM(markup, {url: options.url || 'https://forge.test/', runScripts: 'outside-only', pretendToBeVisual:true});
  for (const [key, value] of Object.entries(options.sessionStorage || {})) dom.window.sessionStorage.setItem(key, value);
  await new Promise(resolve => dom.window.addEventListener('load', resolve, {once: true}));
  const errors = [];
  dom.window.console.error = (...args) => errors.push(args.join(' '));
  dom.window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  dom.window.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new dom.window.Event('close')); };
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

test('long policy members open in a searchable modal without expanding the table row', async () => {
  const values = ['portal.example', 'updates.example', 'ntp.example', 'backup.example'];
  const {dom, document, window, errors} = await page(`<table><tbody><tr><td><button type="button" data-policy-members='${JSON.stringify(values)}'>+2 meer</button></td></tr></tbody></table>`);
  document.querySelector('[data-policy-members]').click();
  const dialog = document.querySelector('.policy-members-dialog');
  assert.equal(dialog.open, true);
  assert.deepEqual([...dialog.querySelectorAll('[data-policy-members-list] span')].map(node => node.textContent), values);
  const search = dialog.querySelector('[data-policy-members-search]');
  search.value = 'ntp'; search.dispatchEvent(new window.Event('input'));
  assert.deepEqual([...dialog.querySelectorAll('[data-policy-members-list] span')].map(node => node.textContent), ['ntp.example']);
  dialog.querySelector('.config-dialog-close').click();
  assert.equal(dialog.open, false);
  assert.equal(document.querySelector('tbody tr').querySelectorAll('span').length, 0, 'values stay outside the table row');
  assert.deepEqual(errors, []); dom.window.close();
});

test('hidden editor fields remain hidden despite layout display rules', async () => {
  const {dom, document, window} = await page(`<style>${styles}</style><div class="field full" data-dynamic-filter hidden>Dynamic filter</div>`);
  assert.equal(window.getComputedStyle(document.querySelector('[data-dynamic-filter]')).display, 'none');
  dom.window.close();
});

test('incremental push select-all selects every available family and tracks partial selection', async () => {
  const {dom, document, window, errors} = await page(`<form data-incremental-push>
    <input type="checkbox" data-push-select-all>
    <input type="checkbox" name="family" data-push-family value="shared-objects">
    <input type="checkbox" name="family" data-push-family value="vsys-policies">
    <input type="checkbox" name="family" value="protected" disabled>
    <button type="submit"></button><input type="checkbox" data-commit-after-push>
    <div data-incremental-push-progress hidden></div></form>`);
  const selectAll = document.querySelector('[data-push-select-all]');
  const families = [...document.querySelectorAll('[data-push-family]')];
  selectAll.click();
  assert.deepEqual(families.map(input => input.checked), [true, true]);
  assert.equal(document.querySelector('[value="protected"]').checked, false, 'protected settings are excluded from select-all');
  assert.equal(selectAll.checked, true);
  families[0].click();
  assert.equal(selectAll.checked, false);
  assert.equal(selectAll.indeterminate, true);
  families[1].click();
  assert.equal(selectAll.checked, false);
  assert.equal(selectAll.indeterminate, false);
  assert.deepEqual(errors, []); dom.window.close();
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

function policyBulkStateMarkup() {
  return `<form data-policy-bulk-form action="/policies/42/preview">
    <table><tbody><tr data-policy-row data-tag="existing"><td><input type="checkbox" data-policy-select value="rule-1"></td></tr></tbody></table>
    <span data-policy-action-count></span><button type="button" data-open-policy-bulk>Bulk edit</button>
    <dialog data-policy-bulk-dialog><span data-policy-selected-count></span>
      <button type="button" data-policy-tab="source" class="is-active"></button>
      <button type="button" data-policy-tab="actions"></button>
      <div data-policy-panel="source" class="is-active">
        <div data-bulk-field="source"><div data-bulk-values></div><input data-bulk-entry data-picker-field="source"><button type="button" data-bulk-add-button></button><input type="hidden" name="source_add" data-bulk-add><input type="hidden" name="source_remove" data-bulk-remove></div>
        <div data-bulk-scalar-field="log_setting"><div data-bulk-scalar-values></div><input data-bulk-scalar-entry data-picker-field="log_setting"><input type="hidden" name="log_setting" data-bulk-scalar-value></div>
      </div>
      <div data-policy-panel="actions"></div>
      <button type="button" data-policy-bulk-cancel>Cancel</button>
    </dialog>
  </form><a href="/objects/new" target="_blank" data-policy-picker-create>Create object</a>`;
}

test('bulk policy edits survive opening object creation and reloading the policy page', async () => {
  const url = 'https://forge.test/?policy_profile=42#policy-management';
  const {dom, document, window} = await page(policyBulkStateMarkup(), {url});
  document.querySelector('[data-policy-select]').click();
  document.querySelector('[data-open-policy-bulk]').click();
  document.querySelector('[data-bulk-add]').value = 'new-address';
  document.querySelector('[data-bulk-remove]').value = 'existing';
  document.querySelector('[data-bulk-entry]').value = 'typed but not added';
  document.querySelector('[data-bulk-scalar-value]').value = 'send-to-siem';
  document.querySelector('[data-policy-tab="actions"]').click();
  document.querySelector('[data-policy-picker-create]').addEventListener('click', event => event.preventDefault(), {once:true, capture:true});
  document.querySelector('[data-policy-picker-create]').click();
  const saved = window.sessionStorage.getItem('ppf-unsaved-policy-bulk-state');
  assert.ok(saved, 'opening object creation should save the current bulk edit');
  dom.window.close();

  const restored = await page(policyBulkStateMarkup(), {url, sessionStorage: {'ppf-unsaved-policy-bulk-state': saved}});
  assert.equal(restored.document.querySelector('[data-policy-bulk-dialog]').open, true);
  assert.equal(restored.document.querySelector('[data-policy-select]').checked, true);
  assert.equal(restored.document.querySelector('[data-bulk-add]').value, 'new-address');
  assert.equal(restored.document.querySelector('[data-bulk-remove]').value, 'existing');
  assert.equal(restored.document.querySelector('[data-bulk-entry]').value, 'typed but not added');
  assert.equal(restored.document.querySelector('[data-bulk-scalar-value]').value, 'send-to-siem');
  assert.equal(restored.document.querySelector('[data-policy-tab="actions"]').classList.contains('is-active'), true);
  assert.deepEqual(restored.errors, []);
  restored.dom.window.close();
});

test('cancelling a bulk dialog clears state saved for object creation', async () => {
  const {dom, document, window} = await page(policyBulkStateMarkup());
  document.querySelector('[data-policy-select]').click();
  document.querySelector('[data-open-policy-bulk]').click();
  document.querySelector('[data-policy-picker-create]').addEventListener('click', event => event.preventDefault(), {once:true, capture:true});
  document.querySelector('[data-policy-picker-create]').click();
  assert.ok(window.sessionStorage.getItem('ppf-unsaved-policy-bulk-state'));

  document.querySelector('[data-policy-bulk-cancel]').click();
  assert.equal(document.querySelector('[data-policy-bulk-dialog]').open, false);
  assert.equal(window.sessionStorage.getItem('ppf-unsaved-policy-bulk-state'), null);
  dom.window.close();
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

test('bug report snapshot skips an uncloneable page widget and surfaces app notices above the modal', async () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app', 'static', 'bug-report.js'), 'utf8');
  const dom = new JSDOM('<!doctype html><html><head></head><body><div class="flash-stack"><div class="flash flash-success" role="status">Syslog is actief</div></div><div id="uncloneable">Widget</div></body></html>', {
    url: 'https://forge.test/', runScripts: 'outside-only', pretendToBeVisual: true,
  });
  const {window} = dom;
  const sources = [];
  let failImageDecode = false;
  window.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  window.HTMLDialogElement.prototype.close = function () {
    this.open = false;
    this.dispatchEvent(new window.Event('close'));
  };
  window.URL.createObjectURL = () => 'blob:preview';
  window.URL.revokeObjectURL = () => {};
  window.Image = class {
    set src(value) { sources.push(value); }
    async decode() {
      if (failImageDecode) throw new window.DOMException('Invalid image data', 'InvalidStateError');
    }
  };
  window.HTMLCanvasElement.prototype.getContext = () => ({drawImage() {}});
  window.HTMLCanvasElement.prototype.toBlob = function (callback) {
    callback(new window.Blob(['png'], {type:'image/png'}));
  };
  window.document.querySelector('#uncloneable').cloneNode = () => {
    throw new window.DOMException('Browser-managed state cannot be cloned', 'InvalidStateError');
  };
  const script = window.document.createElement('script');
  script.dataset.csrf = 'test-token';
  window.document.body.append(script);
  Object.defineProperty(window.document, 'currentScript', {configurable:true, value:script});
  window.eval(source);
  window.document.querySelector('[data-bug-report-launcher]').click();
  await new Promise(resolve => window.setTimeout(resolve, 0));

  assert.equal(sources.length, 1);
  assert.match(sources[0], /^data:image\/svg\+xml;charset=utf-8,/);
  const snapshot = decodeURIComponent(sources[0].split(',', 2)[1]);
  assert.match(snapshot, /<foreignObject/);
  assert.doesNotMatch(snapshot, /uncloneable|Widget/);
  assert.match(window.document.querySelector('[data-capture-status]').textContent, /Screenshot klaar/);
  assert.equal(window.document.querySelector('[data-submit]').disabled, false);
  const priorityNotices = window.document.querySelector('[data-priority-notices]');
  assert.equal(priorityNotices.hidden, false);
  assert.match(priorityNotices.textContent, /Syslog is actief/);

  window.document.querySelector('.flash').textContent = 'Syslog is hersteld';
  await new Promise(resolve => window.setTimeout(resolve, 25));
  assert.match(priorityNotices.textContent, /Syslog is hersteld/);

  window.document.querySelector('[data-close]').click();
  assert.equal(priorityNotices.hidden, true);
  await new Promise(resolve => window.setTimeout(resolve, 0));
  assert.equal(window.document.querySelector('[data-preview]').hasAttribute('src'), false);
  failImageDecode = true;
  window.document.querySelector('[data-bug-report-launcher]').click();
  await new Promise(resolve => window.setTimeout(resolve, 0));
  assert.equal(window.document.querySelector('[data-preview]').hasAttribute('src'), false);
  assert.equal(window.document.querySelector('[data-submit]').disabled, true);
  assert.equal(window.document.querySelector('[data-capture-fallback]').hidden, false);
  window.document.querySelector('[data-close]').click();
  await new Promise(resolve => window.setTimeout(resolve, 25));
  dom.window.close();
});
