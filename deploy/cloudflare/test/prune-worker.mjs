import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { binaryenTools, liveWasmReferences, pruneWorker, verifyPublishedBundle } from '../prune-worker.mjs';

const glue = `
import source module from './index_bg.wasm';
var registry = typeof FinalizationRegistry > 'u'
  ? { register: () => {}, unregister: () => {} }
  : new FinalizationRegistry(ptr => wasm.__wbg_minifyconfig_free(ptr, 1));
var Minify = class {
  static __wrap(ptr) { return new Minify(ptr); }
  constructor(ptr) { this.ptr = ptr; registry.register(this, ptr, this); }
  free() { registry.unregister(this); wasm.__wbg_minifyconfig_free(this.ptr, 0); }
  get css() { return wasm.__wbg_get_minifyconfig_css(this.ptr); }
};
Symbol.dispose && (Minify.prototype[Symbol.dispose] = Minify.prototype.free);
function imports() { return { './index_bg.js': {
  sdk_construct: ptr => Minify.__wrap(ptr),
  active_callback: () => wasm.callback(),
} }; }
var instance = new WebAssembly.Instance(module, imports());
var wasm = instance.exports;
wasm.__wbindgen_start();
var handler = {};
var sdk = new Proxy(Minify, handler);
var application = { fetch() { return wasm.fetch(); }, scheduled() { return wasm.scheduled(); } };
export { sdk as MinifyConfig, application as default };
`;

const wasmText = `(module
  (type $closure (func (result i32)))
  (import "./index_bg.js" "sdk_construct" (func $sdk (param i32) (result i32)))
  (import "./index_bg.js" "active_callback" (func $callback (result i32)))
  (memory (export "memory") 1)
  (global (export "__instance_signal") (mut i32) (i32.const 0))
  (table (export "__wbindgen_export") 1 funcref)
  (elem (i32.const 0) $indirect)
  (func $indirect (result i32) (i32.const 7))
  (func (export "fetch") (result i32) (call $callback))
  (func (export "callback") (result i32) (call_indirect (type $closure) (i32.const 0)))
  (func (export "scheduled") (result i32) (i32.const 9))
  (func (export "__wbindgen_start"))
  (func (export "__wbg_get_minifyconfig_css") (param i32) (result i32) (call $sdk (local.get 0)))
  (func (export "__wbg_minifyconfig_free") (param i32 i32))
)`;

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'nazo-release-prune-'));
  writeFileSync(join(directory, 'input.wat'), wasmText);
  writeFileSync(join(directory, 'index.js'), glue);
  execFileSync(binaryenTools()['wasm-as'], [join(directory, 'input.wat'), '-o', join(directory, 'index_bg.wasm'), '--enable-mutable-globals', '--enable-reference-types']);
  return directory;
}

test('joint JS/WASM pruning removes a dead SDK cycle and preserves callback, table, memory and scheduled behavior', () => {
  const directory = fixture();
  try {
    const result = pruneWorker(directory);
    assert.deepEqual(result.removed_exports.sort(), ['__wbg_get_minifyconfig_css', '__wbg_minifyconfig_free']);
    const code = readFileSync(join(directory, 'index.js'), 'utf8');
    assert.doesNotMatch(code, /MinifyConfig|FinalizationRegistry|sdk_construct|__wbg_.*minifyconfig/);
    const module = new WebAssembly.Module(readFileSync(join(directory, 'index_bg.wasm')));
    const exports = WebAssembly.Module.exports(module).map(entry => entry.name);
    for (const name of ['fetch', 'scheduled', 'callback', 'memory', '__instance_signal', '__wbindgen_export']) assert.ok(exports.includes(name));
    assert.deepEqual(WebAssembly.Module.imports(module).map(entry => entry.name), ['active_callback']);
    let instance;
    instance = new WebAssembly.Instance(module, { './index_bg.js': { active_callback: () => instance.exports.callback() } });
    assert.equal(instance.exports.fetch(), 7);
    assert.equal(instance.exports.scheduled(), 9);
    assert.equal(instance.exports.__wbindgen_export.get(0)(), 7);
    assert.ok(instance.exports.memory instanceof WebAssembly.Memory);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('a genuinely reachable SDK value and its ABI remain available', () => {
  const directory = fixture();
  try {
    writeFileSync(join(directory, 'index.js'), glue.replace('var application = {', 'globalThis.keepSdk = sdk; var application = {'));
    const result = pruneWorker(directory);
    assert.deepEqual(result.removed_exports, []);
    assert.match(readFileSync(join(directory, 'index.js'), 'utf8'), /__wbg_get_minifyconfig_css/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('dynamic or escaped WASM exports stop pruning instead of guessing liveness', () => {
  assert.throws(() => liveWasmReferences(glue.replace('wasm.fetch()', 'wasm[globalThis.method]()')), /dynamic WASM export/);
  assert.throws(() => liveWasmReferences(glue.replace('wasm.fetch()', 'globalThis.inspect(wasm)')), /escapes static member/);
  assert.throws(() => liveWasmReferences(glue.replace('var application = {', 'wasm = globalThis.other; var application = {')), /escapes its instance/);
  assert.throws(() => liveWasmReferences(glue.replace('wasm.fetch()', 'instance.exports.fetch()')), /instance escapes/);
});

test('unknown SDK initialization effects fail before changing generated artifacts', () => {
  const directory = fixture();
  try {
    const before = readFileSync(join(directory, 'index_bg.wasm'));
    for (const changed of [
      glue.replace('var Minify = class {', 'var Minify = class { static { globalThis.sideEffect(); }'),
      glue.replace('free() { registry.unregister(this);', 'get free() { globalThis.sideEffect(); registry.unregister(this);'),
    ]) {
      writeFileSync(join(directory, 'index.js'), changed);
      assert.throws(() => pruneWorker(directory), /unrecognized (initialization effect|free getter)/);
      assert.deepEqual(readFileSync(join(directory, 'index_bg.wasm')), before);
      assert.equal(readFileSync(join(directory, 'index.js'), 'utf8'), changed);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('the final release pair rejects stale WASM filenames and missing live ABI', () => {
  const directory = fixture();
  try {
    pruneWorker(directory);
    const code = readFileSync(join(directory, 'index.js'), 'utf8');
    writeFileSync(join(directory, 'shim.js'), code);
    verifyPublishedBundle(directory);
    writeFileSync(join(directory, 'shim.js'), code.replace('./index_bg.wasm', './old.wasm'));
    assert.throws(() => verifyPublishedBundle(directory), /stale WASM/);
    writeFileSync(join(directory, 'shim.js'), code.replace('.fetch()', '.missingExport()'));
    assert.throws(() => verifyPublishedBundle(directory), /missing WASM export/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
