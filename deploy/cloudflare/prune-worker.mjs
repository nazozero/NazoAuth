// Release-only reachability across worker-build's JavaScript and WASM boundary.
// Binaryen owns all binary parsing and rewriting; unknown JS ABI shapes fail.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import generateModule from '@babel/generator';
import { transformSync } from 'esbuild';

const traverse = traverseModule.default ?? traverseModule;
const generate = generateModule.default ?? generateModule;
const sdkExports = new Set(['ContainerStartupOptions', 'MinifyConfig', 'R2Range']);
// Match worker-build 0.9.0, rather than enabling future encodings such as
// compact imports that this workerd/Node release does not understand.
const binaryenFeatures = ['mutable-globals', 'sign-ext', 'nontrapping-float-to-int',
  'bulk-memory', 'multivalue', 'reference-types', 'exception-handling']
  .map(feature => `--enable-${feature}`);
const inside = (path, node) => path.node.start >= node.start && path.node.end <= node.end;
const propertyName = node => !node.computed && node.property?.type === 'Identifier'
  ? node.property.name : node.property?.type === 'StringLiteral' ? node.property.value : undefined;
const objectKey = node => !node.computed && node.key?.type === 'Identifier'
  ? node.key.name : node.key?.type === 'StringLiteral' ? node.key.value : undefined;
const member = (node, object, property) => node?.type === 'MemberExpression'
  && node.object.type === 'Identifier' && node.object.name === object && propertyName(node) === property;
const construct = (node, object, property) => node?.type === 'NewExpression'
  && (property ? member(node.callee, object, property)
    : node.callee.type === 'Identifier' && node.callee.name === object);
const parseModule = code => parse(code, { sourceType: 'module', plugins: ['sourcePhaseImports'] });

function scopeFor(ast) {
  let program;
  traverse(ast, { Program(path) { program = path; path.stop(); } });
  return program;
}

function wasmBinding(program) {
  const candidates = Object.values(program.scope.bindings).filter(binding => {
    const init = binding.path.node.init;
    if (init?.type !== 'MemberExpression' || propertyName(init) !== 'exports'
      || init.object.type !== 'Identifier') return false;
    return construct(program.scope.getBinding(init.object.name)?.path.node.init, 'WebAssembly', 'Instance');
  });
  assert.equal(candidates.length, 1, 'expected one generated WebAssembly exports binding');
  assert.equal(program.scope.getBinding('WebAssembly'), undefined, 'WebAssembly is shadowed');
  const binding = candidates[0];
  const instance = binding.path.node.init.object.name;
  const instanceBinding = program.scope.getBinding(instance);
  const source = instanceBinding.path.node.init.arguments[0];
  assert.ok(source?.type === 'Identifier' && program.scope.getBinding(source.name)?.path.isImportDefaultSpecifier(),
    'WASM instance does not use a static module import');
  for (const violation of binding.constantViolations) {
    assert.ok(violation.isAssignmentExpression({ operator: '=' })
      && member(violation.node.right, instance, 'exports'), 'WASM exports binding escapes its instance');
  }
  for (const violation of instanceBinding.constantViolations) {
    assert.ok(violation.isAssignmentExpression({ operator: '=' })
      && construct(violation.node.right, 'WebAssembly', 'Instance')
      && violation.node.right.arguments[0]?.type === 'Identifier'
      && violation.node.right.arguments[0].name === source.name, 'WASM instance has an unknown replacement');
  }
  for (const reference of instanceBinding.referencePaths) {
    const access = reference.parentPath;
    const assignment = access.parent;
    assert.ok(access.isMemberExpression() && member(access.node, instance, 'exports')
      && ((assignment.type === 'VariableDeclarator' && assignment.id.type === 'Identifier'
        && assignment.id.name === binding.identifier.name && assignment.init === access.node)
        || (assignment.type === 'AssignmentExpression' && assignment.operator === '='
          && assignment.left.type === 'Identifier' && assignment.left.name === binding.identifier.name
          && assignment.right === access.node)), 'WASM instance escapes its generated exports binding');
  }
  return binding;
}

function wasmReference(path) {
  assert.ok(path.parentPath.isMemberExpression() && path.parent.object === path.node,
    'WASM exports object escapes static member access');
  const name = propertyName(path.parent);
  assert.equal(typeof name, 'string', 'dynamic WASM export access prevents safe pruning');
  return name;
}

function disposalStatement(path, className) {
  if (!path.isExpressionStatement()) return false;
  const expression = path.node.expression;
  if (expression.type !== 'LogicalExpression' || expression.operator !== '&&'
    || !member(expression.left, 'Symbol', 'dispose')) return false;
  const assignment = expression.right;
  return assignment.type === 'AssignmentExpression' && assignment.operator === '='
    && assignment.left.type === 'MemberExpression' && assignment.left.computed
    && member(assignment.left.object, className, 'prototype')
    && member(assignment.left.property, 'Symbol', 'dispose')
    && assignment.right.type === 'MemberExpression'
    && member(assignment.right.object, className, 'prototype')
    && propertyName(assignment.right) === 'free';
}

function finalizerInitializer(node) {
  if (node?.type !== 'ConditionalExpression' || !construct(node.alternate, 'FinalizationRegistry')) return false;
  return node.alternate.arguments.length === 1
    && ['ArrowFunctionExpression', 'FunctionExpression'].includes(node.alternate.arguments[0].type)
    && node.consequent.type === 'ObjectExpression'
    && node.consequent.properties.every(property => property.type === 'ObjectProperty'
      && !property.computed && ['register', 'unregister'].includes(objectKey(property))
      && ['ArrowFunctionExpression', 'FunctionExpression'].includes(property.value.type))
    && node.test.type === 'BinaryExpression'
    && node.test.left.type === 'UnaryExpression' && node.test.left.operator === 'typeof'
    && node.test.left.argument.type === 'Identifier' && node.test.left.argument.name === 'FinalizationRegistry'
    && node.test.right.type === 'StringLiteral';
}

/** Model only generated glue; all unrecognized top-level effects stay roots. */
export function analyzeGlue(code, exports, imports) {
  const ast = parseModule(code);
  const program = scopeFor(ast);
  traverse(ast, { CallExpression(path) {
    assert.ok(!(path.node.callee.type === 'Identifier' && path.node.callee.name === 'eval'),
      'direct eval prevents static glue reachability');
  } });
  const wasm = wasmBinding(program);
  const exportedNames = new Set(exports.map(entry => entry.name));
  const bindings = Object.values(program.scope.bindings);
  const prunable = new Set();
  const disposals = [];
  const removedExports = [];
  for (const declaration of program.get('body').filter(path => path.isExportNamedDeclaration())) {
    assert.equal(declaration.node.source, null, 'unexpected generated re-export');
    assert.equal(declaration.node.declaration, null, 'unexpected inline generated export');
    for (const specifier of declaration.get('specifiers')) {
      const name = specifier.node.exported.name;
      if (name === 'default') continue;
      assert.ok(sdkExports.has(name), `unknown generated named export ${name}`);
      const wrapper = program.scope.getBinding(specifier.node.local.name);
      const init = wrapper?.path.node.init;
      assert.ok(wrapper?.constant && construct(init, 'Proxy') && init.arguments.length === 2
        && init.arguments.every(argument => argument.type === 'Identifier'), 'SDK export wrapper changed');
      const cls = program.scope.getBinding(init.arguments[0].name);
      assert.ok(cls?.constant && cls.path.node.init?.type === 'ClassExpression'
        && cls.path.node.init.superClass === null
        && cls.path.node.init.body.body.every(method => method.type === 'ClassMethod' && !method.computed),
      'SDK class has an unrecognized initialization effect');
      const free = cls.path.node.init.body.body.filter(method => method.key.type === 'Identifier' && method.key.name === 'free');
      assert.ok(free.length === 1 && free[0].kind === 'method' && !free[0].static,
        'SDK disposal could invoke an unrecognized free getter');
      assert.equal(program.scope.getBinding('Proxy'), undefined, 'Proxy is shadowed');
      assert.equal(program.scope.getBinding('Symbol'), undefined, 'Symbol is shadowed');
      prunable.add(wrapper.identifier.name);
      prunable.add(cls.identifier.name);
      const disposal = program.get('body').filter(path => disposalStatement(path, cls.identifier.name));
      assert.equal(disposal.length, 1, 'SDK disposal contract changed');
      disposals.push({ path: disposal[0], owner: cls.identifier.name });
      removedExports.push(specifier);
    }
  }
  for (const binding of bindings) {
    if (finalizerInitializer(binding.path.node.init)) {
      assert.equal(program.scope.getBinding('FinalizationRegistry'), undefined, 'FinalizationRegistry is shadowed');
      prunable.add(binding.identifier.name);
    }
  }
  const importProperties = [];
  const propertyPaths = [];
  traverse(ast, { ObjectProperty(path) { propertyPaths.push(path); } });
  for (const entry of imports) {
    const matches = propertyPaths.filter(path => objectKey(path.node) === entry.name
      && path.parentPath.isObjectExpression() && path.parentPath.parentPath.isObjectProperty()
      && objectKey(path.parentPath.parent) === entry.module);
    if (matches.length === 0) {
      // esbuild represents imported snippet namespaces as an object populated
      // by top-level defineProperty calls. Those effects remain conservative
      // JS roots; do not infer individual namespace members from their names.
      const namespaces = propertyPaths.filter(path => objectKey(path.node) === entry.module
        && path.node.value.type === 'Identifier' && program.scope.getBinding(path.node.value.name));
      assert.equal(namespaces.length, 1, `WASM import ${entry.module}.${entry.name} is not statically described`);
      importProperties.push({ path: namespaces[0], entry, opaque: true, name: `import:${entry.module}:${entry.name}` });
      continue;
    }
    assert.equal(matches.length, 1, `WASM import ${entry.module}.${entry.name} is ambiguous`);
    const path = matches[0];
    assert.ok(['FunctionExpression', 'ArrowFunctionExpression', 'Identifier'].includes(path.node.value.type)
      || (entry.kind === 'tag' && member(path.node.value, 'WebAssembly', 'JSTag')),
      `WASM import ${entry.module}.${entry.name} initializer ${path.node.value.type} has an unknown effect`);
    importProperties.push({ path, entry, name: `import:${entry.module}:${entry.name}` });
  }
  const nodes = new Map([['outside', { name: 'outside', root: true, reaches: new Set() }]]);
  for (const binding of bindings) {
    const name = binding.identifier.name;
    nodes.set(`js:${name}`, { name: `js:${name}`, reaches: new Set(),
      ...(!prunable.has(name) && !binding.path.isFunctionDeclaration() ? { root: true } : {}) });
  }
  for (const entry of exports) {
    nodes.set(`export:${entry.name}`, { name: `export:${entry.name}`, export: entry.name, reaches: new Set(),
      ...(entry.kind !== 'function' ? { root: true } : {}) });
  }
  for (const entry of importProperties) {
    nodes.set(entry.name, { name: entry.name, import: [entry.entry.module, entry.entry.name],
      reaches: new Set(entry.opaque ? [`js:${entry.path.node.value.name}`] : []) });
  }
  const owner = path => {
    if (removedExports.some(specifier => inside(path, specifier.node))) return undefined;
    const imported = importProperties.find(item => !item.opaque && inside(path, item.path.node.value));
    if (imported) return imported.name;
    const disposal = disposals.find(item => inside(path, item.path.node));
    if (disposal) return `js:${disposal.owner}`;
    const declaration = bindings.find(binding => inside(path, binding.path.node));
    return declaration ? `js:${declaration.identifier.name}` : 'outside';
  };
  for (const binding of bindings) {
    for (const reference of binding.referencePaths) {
      const from = owner(reference);
      if (!from) continue;
      if (binding === wasm) {
        const name = wasmReference(reference);
        assert.ok(exportedNames.has(name), `JavaScript references missing WASM export ${name}`);
        nodes.get(from).reaches.add(`export:${name}`);
      } else {
        nodes.get(from).reaches.add(`js:${binding.identifier.name}`);
      }
    }
    // Writes can occur in reinitialization routines as well as initializers.
    for (const assignment of binding.constantViolations) {
      const from = owner(assignment);
      if (from) nodes.get(from).reaches.add(`js:${binding.identifier.name}`);
    }
  }
  return { ast, bindings, prunable, disposals, removedExports, importProperties,
    graph: [...nodes.values()].map(node => ({ ...node, reaches: [...node.reaches] })) };
}

export function liveWasmReferences(code) {
  const program = scopeFor(parseModule(code));
  return new Set(wasmBinding(program).referencePaths.map(wasmReference));
}

/** Check Wrangler's actual published JS/WASM pair, not just its build inputs. */
export function verifyPublishedBundle(directory) {
  const files = readdirSync(directory);
  const binaries = files.filter(name => name.endsWith('.wasm'));
  assert.equal(binaries.length, 1, 'a release must contain exactly one current WASM module');
  const code = readFileSync(join(directory, 'shim.js'), 'utf8');
  const ast = parseModule(code);
  const exports = ast.program.body.filter(node => node.type === 'ExportNamedDeclaration')
    .flatMap(node => node.specifiers.map(specifier => specifier.exported.name));
  assert.deepEqual(exports, ['default'], 'only the Worker application is a public JavaScript export');
  const wasmImports = ast.program.body.filter(node => node.type === 'ImportDeclaration' && node.source.value.endsWith('.wasm'));
  assert.equal(wasmImports.length, 1, 'release JS must statically import its WASM module');
  assert.equal(wasmImports[0].source.value, `./${binaries[0]}`, 'release references a stale WASM module');
  const names = new Set(WebAssembly.Module.exports(new WebAssembly.Module(readFileSync(join(directory, binaries[0]))))
    .map(entry => entry.name));
  for (const name of liveWasmReferences(code)) assert.ok(names.has(name), `release references missing WASM export ${name}`);
}

export function binaryenTools() {
  const executable = platform() === 'win32' ? '.exe' : '';
  const roots = [];
  if (process.env.WASM_METADCE_BIN) roots.push(dirname(resolve(process.env.WASM_METADCE_BIN)));
  if (process.env.WASM_OPT_BIN) roots.push(dirname(resolve(process.env.WASM_OPT_BIN)));
  const cache = join(process.env.XDG_CACHE_HOME ?? (platform() === 'darwin'
    ? join(homedir(), 'Library/Caches') : join(homedir(), '.cache')), 'worker-build');
  if (existsSync(cache)) {
    for (const entry of readdirSync(cache).filter(name => name.startsWith('wasm-opt-') && name.endsWith('-133'))) {
      roots.push(join(cache, entry, 'bin'));
    }
  }
  for (const directory of roots) {
    const tools = Object.fromEntries(['wasm-opt', 'wasm-metadce', 'wasm-as'].map(name => [name, join(directory, name + executable)]));
    if (!existsSync(tools['wasm-opt']) || !existsSync(tools['wasm-metadce'])) continue;
    for (const name of ['wasm-opt', 'wasm-metadce']) {
      assert.match(execFileSync(tools[name], ['--version'], { encoding: 'utf8' }), /version 133\b/,
        'release pruning requires the Binaryen version pinned by worker-build');
    }
    return tools;
  }
  throw new Error('Complete Binaryen 133 tools are required; use worker-build cache or WASM_OPT_BIN/WASM_METADCE_BIN from that distribution');
}

export function pruneWorker(directory) {
  const tools = binaryenTools();
  const jsPath = join(directory, 'index.js');
  const wasmPath = join(directory, 'index_bg.wasm');
  const originalJs = readFileSync(jsPath, 'utf8');
  const originalWasm = readFileSync(wasmPath);
  const originalModule = new WebAssembly.Module(originalWasm);
  const before = WebAssembly.Module.exports(originalModule);
  const analysis = analyzeGlue(originalJs, before, WebAssembly.Module.imports(originalModule));
  const temporary = mkdtempSync(join(directory, '.prune-'));
  try {
    const graph = join(temporary, 'graph.json');
    const pruned = join(temporary, 'pruned.wasm');
    const optimized = join(temporary, 'index_bg.wasm');
    writeFileSync(graph, JSON.stringify(analysis.graph));
    const report = execFileSync(tools['wasm-metadce'], [wasmPath, '--graph-file', graph, '-o', pruned, ...binaryenFeatures], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
    const unused = new Set(report.split(/\r?\n/).filter(line => line.startsWith('unused: ')).map(line => line.slice(8)));
    const retainedImports = new Set(WebAssembly.Module.imports(new WebAssembly.Module(readFileSync(pruned)))
      .map(entry => `${entry.module}:${entry.name}`));
    const removedProperties = new Set();
    for (const { path, entry, opaque } of analysis.importProperties) {
      const removed = opaque ? ![...retainedImports].some(name => name.startsWith(`${entry.module}:`))
        : !retainedImports.has(`${entry.module}:${entry.name}`);
      if (removed && !removedProperties.has(path)) { removedProperties.add(path); path.remove(); }
    }
    for (const path of analysis.removedExports) path.remove();
    for (const { path, owner } of analysis.disposals) if (unused.has(`js:${owner}`)) path.remove();
    for (const binding of analysis.bindings) {
      const name = binding.identifier.name;
      if (analysis.prunable.has(name) && unused.has(`js:${name}`)) binding.path.remove();
    }
    const code = transformSync(generate(analysis.ast).code, {
      format: 'esm', target: 'esnext', minify: true, treeShaking: true,
    }).code;
    execFileSync(tools['wasm-opt'], [pruned, '-O3', '--remove-unused-module-elements', '-o', optimized, ...binaryenFeatures], { maxBuffer: 1024 * 1024 });
    const bytes = readFileSync(optimized);
    const after = WebAssembly.Module.exports(new WebAssembly.Module(bytes));
    const names = new Set(after.map(entry => entry.name));
    for (const name of liveWasmReferences(code)) assert.ok(names.has(name), `pruning removed live WASM export ${name}`);
    for (const entry of before.filter(entry => entry.kind !== 'function')) {
      assert.ok(names.has(entry.name), `pruning removed ${entry.kind} ${entry.name}`);
    }
    const result = { before_bytes: originalWasm.length, after_bytes: bytes.length,
      before_gzip_bytes: gzipSync(originalWasm, { level: 9 }).length,
      after_gzip_bytes: gzipSync(bytes, { level: 9 }).length,
      before_exports: before.length, after_exports: after.length,
      removed_exports: before.filter(entry => !names.has(entry.name)).map(entry => entry.name),
      before_javascript_bytes: Buffer.byteLength(originalJs), after_javascript_bytes: Buffer.byteLength(code) };
    writeFileSync(join(temporary, 'index.js'), code);
    // All analysis, Binaryen validation and JS ABI checks succeed before replacing
    // either generated input. The build command stops on any failed contract.
    renameSync(optimized, wasmPath);
    renameSync(join(temporary, 'index.js'), jsPath);
    writeFileSync(join(directory, 'prune-report.json'), JSON.stringify(result, null, 2) + '\n');
    return result;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = resolve(process.argv[2] ?? fileURLToPath(new URL('../../crates/server-worker/build', import.meta.url)));
  console.log(JSON.stringify(pruneWorker(directory)));
}
