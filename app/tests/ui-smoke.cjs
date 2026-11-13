// No browser dependencies: exercise the native-event view and its memory cap.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
class Element {
  constructor() { this.children = []; this.hidden = false; this.value = ''; this.dataset = {}; this.handlers = {}; this.classList = {add(){}, remove(){}}; }
  setAttribute(name,value) { this[name] = value; }
  prepend(...elements) { for(const element of elements.reverse()) { element.parent = this; this.children.unshift(element); } }
  append(...elements) { for(const element of elements) { element.parent = this; this.children.push(element); } }
  remove() { if(this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  replaceChildren() { this.children = []; }
  addEventListener(name, handler) { this.handlers[name] = handler; }
}
const elements = new Map();
const get = selector => { if(!elements.has(selector)) elements.set(selector, new Element()); return elements.get(selector); };
const commands = [];
const context = vm.createContext({ document: {querySelector:get, createElement:()=>new Element(), documentElement:new Element()}, localStorage:{getItem:()=>null,setItem(){}}, window:{webkit:{messageHandlers:{scanner:{postMessage:message=>commands.push(message)}}}} });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../ui/src/main.js'), 'utf8'), context);
assert.equal(commands.shift(), 'ready');
const event = context.window.onNativeEvent;
event({event:'config',signatures:3,clam:false,clamLoading:false});
event({event:'started'});
assert.equal(get('#chooseFile').disabled, true);
const row = (i, status = i === 0 ? 'match' : 'unknown') => ({path:`/tmp/file-${i}`,size:10,kind:'Text',hash:'a'.repeat(64),status,details:[]});
const batch = (from, n, extra = {}) => ({event:'scan',rows:Array.from({length:n},(_,j)=>row(from+j)),done:false,cancelled:false,files:from+n,bytes:10*(from+n),seconds:1,workers:2,matches:1,reviews:0,errors:0,skipped:0,...extra});
for(let i=0;i<1200;i+=60) event(batch(i, 60));
// Only problem rows are DOM nodes by default; 1199 clean files stay as data.
assert.equal(get('#scanList').children.length, 1);
assert.equal(get('#scanList').children[0].children[0].children[0].textContent, '/tmp/file-0');
assert.equal(get('#cleanList').children.length, 0);
assert.equal(get('#emptyList').hidden, true);
// A threat arriving later is placed above earlier problems.
event({...batch(1200, 0), rows:[row(1200, 'review'), row(1201, 'match')], files:1202});
assert.deepEqual(get('#scanList').children.map(r=>r.children[0].children[0].textContent), ['/tmp/file-1201','/tmp/file-0','/tmp/file-1200']);
// "Show all" renders clean files one page at a time.
get('#onlyProblemsBtn').handlers.click();
assert.equal(get('#cleanList').children.length, 500);
assert.equal(get('#moreClean').hidden, false);
get('#moreClean').handlers.click();
get('#moreClean').handlers.click();
assert.equal(get('#cleanList').children.length, 1199);
assert.equal(get('#moreClean').hidden, true);
// Search filters problems and clean files.
get('#filter').value = 'file-12';
get('#filter').handlers.input();
assert.deepEqual(get('#scanList').children.filter(r=>!r.hidden).map(r=>r.children[0].children[0].textContent), ['/tmp/file-1201','/tmp/file-1200']);
assert.equal(get('#cleanList').children.length, 11); // file-12, file-120..129
get('#filter').value = 'nothing-matches';
get('#filter').handlers.input();
assert.equal(get('#emptyList').hidden, false);
get('#filter').value = ''; get('#filter').handlers.input();
get('#onlyProblemsBtn').handlers.click();
assert.equal(get('#cleanList').children.length, 0);
event({...batch(1202, 0), done:true, cancelled:true, files:1202});
assert.equal(get('#chooseFile').disabled,false);
assert.equal(get('#cancel').disabled,true);
assert.equal(get('#verdict').dataset.state,'partial');
assert(get('#announce').textContent.startsWith('Проверка остановлена'));
assert.equal(commands.filter(c=>c==='ack').length, 22);
// A clean finished scan explains why the list is empty.
event({event:'started'});
event({...batch(0, 5), rows:Array.from({length:5},(_,j)=>row(j,'unknown')), matches:0, done:true, files:5});
assert.equal(get('#verdict').dataset.state,'safe');
assert.equal(get('#emptyList').hidden,false);
assert.match(get('#emptyList').textContent, /все проверенные файлы чистые \(5\)/);
get('#clear').handlers.click();
assert.equal(get('#scanList').children.length,0);
assert.equal(get('#scan').hidden,true);
console.log('UI passed: native events, lazy clean rows, threat ordering, search, empty states, cancel, clear, backpressure acknowledgments.');

get('#quickDownloads').handlers.click();
assert.match(commands.at(-1), /^pick:downloads:/);
get('#optHashes').handlers.click();
assert.equal(context.document.documentElement.dataset.hashes, 'off');
get('#autoToggle').handlers.click();
assert.equal(commands.at(-1), 'auto-toggle');
event({event:'auto', enabled:true});
assert.equal(get('#autoToggle')['aria-pressed'], 'true');
assert.equal(get('#autoToggle').textContent, 'Выключить');
event({event:'auto', enabled:false});
assert.equal(get('#autoToggle')['aria-pressed'], 'false');
console.log('Russian auto-mode toggle passed.');

assert.equal(get('#databaseCount').textContent, '3');
assert.equal(get('#totalCount').textContent, '5');
assert.equal(get('#findingCount').textContent, '0');

// Windows WebView2 must use the same protocol without the Linux bridge.
const windowsCommands = [];
const windowsContext = vm.createContext({document: {querySelector:get, createElement:()=>new Element(), documentElement:new Element()}, localStorage:{getItem:()=>null,setItem(){}}, window:{chrome:{webview:{postMessage:message=>windowsCommands.push(message)}}}});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../ui/src/main.js'), 'utf8'), windowsContext);
assert.equal(windowsCommands.shift(), 'ready');
get('#autoToggle').handlers.click();
assert.equal(windowsCommands.at(-1), 'auto-toggle');
console.log('Windows WebView2 bridge passed.');

// Plain verdicts: threat > suspicious > incomplete > clean.
const finish = (extra) => { event({event:'started'}); event({event:'scan',rows:[],done:true,cancelled:false,files:5,bytes:50,seconds:1,workers:2,matches:0,reviews:0,errors:0,skipped:0,...extra}); return get('#verdict').dataset.state; };
assert.equal(finish({}), 'safe');
assert.equal(get('#verdictTitle').textContent, 'Вирусов не найдено');
assert.equal(finish({reviews:2}), 'review');
assert.equal(finish({errors:1}), 'partial');
assert.equal(finish({matches:1,reviews:2,errors:1}), 'threat');
assert.equal(finish({files:0}), 'partial');
console.log('Verdict states passed.');
