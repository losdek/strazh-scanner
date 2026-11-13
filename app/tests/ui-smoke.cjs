// No browser dependencies: exercise the native-event view and its memory cap.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
class Element {
  constructor() { this.children = []; this.hidden = false; this.value = ''; this.dataset = {}; this.handlers = {}; this.classList = {add(){}, remove(){}}; }
  setAttribute(name,value) { this[name] = value; }
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
const row = i => ({path:`/tmp/file-${i}`,size:10,kind:'Text',hash:'a'.repeat(64),status:i===0?'match':'unknown',details:[]});
for(let i=0;i<1200;i+=60) event({event:'scan',rows:Array.from({length:60},(_,j)=>row(i+j)),done:false,cancelled:false,files:i+60,bytes:10*(i+60),seconds:1,workers:2,matches:1,reviews:0,errors:0,skipped:0});
assert.equal(get('#scanList').children.length, 1200);
assert.equal(get('#scanList').children[0].children[0].children[0].textContent, '/tmp/file-0');
assert.equal(get('#scanList').children.filter(row=>!row.hidden).length, 1); // only the match by default
get('#onlyProblemsBtn').handlers.click();
assert.equal(get('#scanList').children.filter(row=>!row.hidden).length, 1200);
event({event:'scan',rows:[],done:true,cancelled:true,files:1200,bytes:12000,seconds:1,workers:2,matches:1,reviews:0,errors:0,skipped:0});
assert.equal(get('#chooseFile').disabled,false);
assert.equal(get('#cancel').disabled,true);
assert.equal(get('#verdict').dataset.state,'partial');
assert(commands.filter(c=>c==='ack').length===21);
get('#clear').handlers.click();
assert.equal(get('#scanList').children.length,0);
assert.equal(get('#scan').hidden,true);
console.log('UI passed: native events, no row cap, cancel completion, clear, backpressure acknowledgments.');

get('#quickDownloads').handlers.click();
assert.match(commands.at(-1), /^pick:downloads:/);
get('#optHashes').handlers.click();
assert.equal(context.document.documentElement.dataset.hashes, 'off');
get('#autoToggle').handlers.click();
assert.equal(commands.at(-1), 'auto-toggle');
event({event:'auto', enabled:true});
assert.equal(get('#autoToggle')['aria-pressed'], 'true');
assert.equal(get('#autoToggle').textContent, 'Выключить автопроверку');
event({event:'auto', enabled:false});
assert.equal(get('#autoToggle')['aria-pressed'], 'false');
console.log('Russian auto-mode toggle passed.');

assert.equal(get('#databaseCount').textContent, '3');
assert.equal(get('#totalCount').textContent, '1 200');
assert.equal(get('#findingCount').textContent, '1');

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
