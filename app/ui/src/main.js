const $ = (selector) => document.querySelector(selector);
const ru = (n) => n.toLocaleString('ru-RU');
let running = false;
let lastMode = 'static';
let modeTouched = false;
let configured = false;
let clamReady = false;
let lastTotals = {files: 0, done: false};
const controls = ['chooseFile', 'chooseFolder', 'quickDownloads', 'quickDesktop', 'quickHome', 'import', 'clear', 'modeHashes', 'modeStatic', 'w1', 'w2', 'w4'];
const MODES = {hashes: 'modeHashes', static: 'modeStatic', clam: 'modeClam'};
const LOADS = {1: 'w1', 2: 'w2', 4: 'w4'};
const IDLE_TITLE = 'Что проверим?';
const IDLE_TEXT = 'Файлы не запускаются и не покидают компьютер.';

/* Кнопки-переключатели вместо выпадающих списков; бегунок плавно переезжает. */
function choose(ids, field, value) {
  const f = field && $(field); if (f) f.value = String(value);
  for (const [v, id] of Object.entries(ids)) {
    const on = String(v === String(value));
    $('#' + id).dataset.on = on;
    $('#' + id).setAttribute('aria-checked', on);
  }
  const target = $('#' + ids[value]);
  const thumb = target.parentElement?.querySelector?.('.thumb');
  if (thumb && target.offsetWidth) { thumb.style.width = target.offsetWidth + 'px'; thumb.style.transform = `translateX(${target.offsetLeft - 3}px)`; }
}
const setMode = (v) => choose(MODES, '#mode', v);
const setLoad = (v) => choose(LOADS, '#workers', v);

function send(message) {
  const bridge = window.webkit?.messageHandlers?.scanner || window.chrome?.webview;
  if (!bridge) { notice('Откройте приложение через run.sh.'); return; }
  bridge.postMessage(message);
}
function notice(message) { $('#notice').hidden = false; $('#notice').textContent = message; }
/* Для экранного диктора: только начало и итог, не каждый пакет. */
function announce(message) { $('#announce').textContent = message; }
function busy(value) {
  running = value;
  for (const id of controls) $('#' + id).disabled = value;
  $('#modeClam').disabled = value || !clamReady;
  $('#cancel').disabled = !value;
}
function bytes(value) {
  const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ'];
  let i = 0; while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
  return `${value.toFixed(i ? 1 : 0)} ${units[i]}`;
}
function duration(seconds) {
  const s = Math.floor(seconds), h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, r = String(s % 60).padStart(2, '0');
  return h ? `${h}:${String(m).padStart(2, '0')}:${r}` : `${m}:${r}`;
}
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many);
}
const files = (n) => `${ru(n)} ${plural(n, 'файл', 'файла', 'файлов')}`;
function setText(selector, value) {
  const el = $(selector);
  if (el.textContent === value) return;
  el.textContent = value;
  el.classList.remove('tick'); void el.offsetWidth; el.classList.add('tick');
}

/* Один из понятных ответов. */
function verdict(state, title, text) {
  const v = $('#verdict');
  const changed = v.dataset.state !== state || $('#verdictTitle').textContent !== title;
  v.dataset.state = state;
  if (changed) for (const id of ['#verdictTitle', '#verdictText']) { const el = $(id); el.classList.remove('swap'); void el.offsetWidth; el.classList.add('swap'); }
  $('#verdictTitle').textContent = title;
  $('#verdictText').textContent = text;
}
function finalVerdict(e) {
  const threats = e.matches, suspicious = e.reviews;
  if (e.cancelled) {
    verdict('partial', 'Проверка остановлена', `Успели проверить ${files(e.files)}.`);
  } else if (threats > 0) {
    verdict('threat', 'Найдены вирусы', `${ru(threats)} ${plural(threats, 'опасный файл', 'опасных файла', 'опасных файлов')}. Не открывайте ${plural(threats, 'его', 'их', 'их')} — лучше удалить.`);
  } else if (suspicious > 0) {
    verdict('review', 'Есть подозрительные файлы', `Вирусов нет, но ${ru(suspicious)} ${plural(suspicious, 'файл ведёт', 'файла ведут', 'файлов ведут')} себя странно. Открывайте, только если доверяете источнику.`);
  } else if (e.files === 0 && e.errors === 0) {
    verdict('partial', 'Нечего проверять', 'Здесь нет файлов для проверки.');
  } else if (e.errors > 0) {
    verdict('partial', 'Проверено не всё', `Вирусов нет, но ${files(e.errors)} не удалось открыть.`);
  } else {
    verdict('safe', 'Вирусов не найдено', `${files(e.files)} — всё чисто. Проверка заняла ${duration(e.seconds)}.`);
  }
  announce(`${$('#verdictTitle').textContent}. ${$('#verdictText').textContent}`);
  const state = $('#verdict').dataset.state;
  if (state === 'threat') beep();
  if (!e.cancelled && e.files > 0) { store.set('strazh-last', JSON.stringify({when: Date.now(), state, files: e.files})); showLast(); }
}

/* Личные настройки окна: тема, анимация, звук, хеши, показ всех файлов. Хранятся только в этом окне. */
const PREFS = {theme: 'auto', motion: true, sound: false, hashes: true, all: false};
const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch {} } };
try { Object.assign(PREFS, JSON.parse(store.get('strazh-prefs') || '{}')); } catch {}
const THEMES = {auto: 'themeAuto', light: 'themeLight', dark: 'themeDark'};
const SWITCHES = {motion: 'optMotion', sound: 'optSound', hashes: 'optHashes', all: 'optAll'};
function applyPrefs() {
  const root = document.documentElement;
  if (PREFS.theme === 'auto') delete root.dataset.theme; else root.dataset.theme = PREFS.theme;
  root.dataset.motion = PREFS.motion ? 'on' : 'off';
  root.dataset.hashes = PREFS.hashes ? 'on' : 'off';
  choose(THEMES, null, PREFS.theme);
  for (const [k, id] of Object.entries(SWITCHES)) $('#' + id).setAttribute('aria-checked', String(!!PREFS[k]));
  store.set('strazh-prefs', JSON.stringify(PREFS));
}
function beep() {
  if (!PREFS.sound || typeof AudioContext === 'undefined') return;
  try { const ctx = new AudioContext(), o = ctx.createOscillator(), g = ctx.createGain();
    o.frequency.value = 660; g.gain.setValueAtTime(.15, ctx.currentTime); g.gain.exponentialRampToValueAtTime(.001, ctx.currentTime + .5);
    o.connect(g).connect(ctx.destination); o.start(); o.stop(ctx.currentTime + .5); } catch {}
}
/* Последняя проверка — одна строка на главном экране. */
function showLast() {
  let last = null; try { last = JSON.parse(store.get('strazh-last') || 'null'); } catch {}
  if (!last) { $('#lastScan').textContent = ''; return; }
  const d = new Date(last.when), today = new Date().toDateString() === d.toDateString();
  const when = (today ? 'сегодня ' : d.toLocaleDateString('ru-RU') + ' ') + d.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'});
  const what = {safe: 'чисто', threat: 'найдены вирусы', review: 'есть подозрительные', partial: 'не полностью'}[last.state] || '';
  $('#lastScan').textContent = `Последняя проверка: ${when} · ${files(last.files)} · ${what}`;
}

const REVIEW = {
  'encoded command or Base64 decoding in text/script': 'закодированная команда или декодирование Base64',
  'downloader and shell execution constructs in the same script': 'загрузка данных и запуск команд в одном сценарии',
  'executable bytes disguised with a document/media extension': 'программа замаскирована под документ или медиафайл',
  'double extension hides a runnable file type': 'двойное расширение скрывает запускаемый файл',
  'hidden or policy-bypassing PowerShell window': 'скрытый запуск PowerShell или обход ограничений',
  'Windows tools commonly abused to download or run code': 'системные утилиты Windows, которыми часто скачивают вредоносный код',
  'reverse-shell construct': 'признаки удалённого доступа к компьютеру (reverse shell)',
  'obfuscated JavaScript execution': 'запутанный JavaScript, скрывающий действия',
};
const DICTIONARY = {'Data':'Данные','Windows executable':'Программа Windows','Linux executable':'Программа Linux','macOS executable':'Программа macOS','PDF':'Документ PDF','ZIP archive':'Архив ZIP','PNG image':'Изображение PNG','JPEG image':'Изображение JPEG','GIF image':'Изображение GIF','Script':'Сценарий','Text':'Текст','RAR archive':'Архив RAR','7-Zip archive':'Архив 7-Zip','Gzip archive':'Архив Gzip','Office document':'Документ Office','Empty':'Пустой файл','Java class/macOS binary':'Java / программа macOS','EICAR harmless antivirus test pattern':'Безопасный тестовый образец EICAR (проверка антивирусов)','ClamAV: no signature match (within daemon scan limits)':'ClamAV: угроз не найдено','File changed during scanning; scan it again':'Файл изменился во время проверки. Проверьте его ещё раз.','Not a regular file':'Это не обычный файл'};
function russian(text) {
  if (DICTIONARY[text]) return DICTIONARY[text];
  if (text.startsWith('Review: ')) { const label = text.slice(8); return 'Подозрительно: ' + (REVIEW[label] || label); }
  if (text.startsWith('ClamAV: ') && !text.startsWith('ClamAV: no')) return 'ClamAV нашёл угрозу: ' + text.slice(8);
  return text.replace('Hash intelligence:', 'Файл есть в базе угроз:').replace('Imported blocklist:', 'Файл есть в вашем списке:').replace('ClamAV incomplete:', 'ClamAV не смог завершить проверку:');
}

/* Результаты. Проблемные файлы всегда в DOM (угрозы сверху). Чистые хранятся как данные
   и рисуются порциями только по запросу — проверка домашней папки не создаёт сотни тысяч узлов. */
const CLEAN_PAGE = 500;
const BADGE = {match: 'Угроза', review: 'Подозрительный', unknown: 'Чисто', empty: 'Пустой файл', error: 'Не проверен'};
let problems = [];     // {element, search}
let clean = [];        // отчёты о чистых файлах
let cleanLimit = CLEAN_PAGE;
let cleanRendered = 0; // сколько подходящих под поиск чистых строк нарисовано
let cleanMatches = 0;  // сколько чистых файлов подходит под поиск
let query = '';
let showAll = false;
const searchText = (report) => (report.path + ' ' + (report.hash || '')).toLowerCase();
function row(report) {
  const li = document.createElement('li'); li.className = 'scan-row';
  li.dataset.tone = report.status === 'match' ? 'bad' : report.status;
  const top = document.createElement('div'); top.className = 'scan-row-top';
  const name = document.createElement('span'); name.className = 'scan-name'; name.textContent = report.path; name.title = report.path;
  const meta = document.createElement('span'); meta.className = 'scan-meta'; meta.textContent = `${russian(report.kind)} · ${bytes(report.size)}`;
  const badge = document.createElement('span'); badge.className = 'scan-badge'; badge.textContent = BADGE[report.status] || report.status;
  top.append(name, meta, badge); li.append(top);
  if (report.hash && report.status !== 'unknown') {
    const hash = document.createElement('div'); hash.className = 'scan-hash'; hash.textContent = report.hash; hash.title = 'SHA-256 — выделите, чтобы скопировать'; li.append(hash);
  }
  const details = report.details.filter(d => report.status !== 'unknown' || !d.startsWith('ClamAV: no'));
  if (details.length) { const d = document.createElement('div'); d.className = 'scan-details'; d.textContent = details.map(russian).join('\n'); li.append(d); }
  return li;
}
function addReport(report) {
  if (['match', 'review', 'error'].includes(report.status)) {
    const element = row(report), search = searchText(report);
    element.hidden = !search.includes(query);
    problems.push({element, search});
    if (report.status === 'match') $('#scanList').prepend(element); else $('#scanList').append(element);
  } else {
    clean.push(report);
    if (!searchText(report).includes(query)) return;
    cleanMatches++;
    if (showAll && cleanRendered < cleanLimit) { $('#cleanList').append(row(report)); cleanRendered++; }
  }
}
/* Полная перерисовка чистого списка: при смене поиска, «Показать все» или «Показать ещё». */
function renderClean() {
  const list = $('#cleanList'); list.replaceChildren(); cleanRendered = 0; cleanMatches = 0;
  for (const report of clean) {
    if (!searchText(report).includes(query)) continue;
    cleanMatches++;
    if (showAll && cleanRendered < cleanLimit) { list.append(row(report)); cleanRendered++; }
  }
}
function updateListChrome() {
  const visibleProblems = problems.filter(p => !p.element.hidden).length;
  $('#cleanList').hidden = !showAll || cleanRendered === 0;
  $('#cleanHead').hidden = $('#cleanList').hidden;
  $('#cleanHead').textContent = `Чистые файлы · ${ru(cleanMatches)}`;
  const more = $('#moreClean'), remaining = cleanMatches - cleanRendered;
  more.hidden = !showAll || remaining <= 0;
  more.textContent = `Показать ещё ${ru(Math.min(CLEAN_PAGE, remaining))} из ${ru(remaining)}`;
  const empty = $('#emptyList');
  let message = '';
  if (query && visibleProblems === 0 && (!showAll || cleanMatches === 0)) message = 'Ничего не найдено.';
  else if (!query && !showAll && visibleProblems === 0 && lastTotals.files > 0)
    message = lastTotals.done ? `Проблемных файлов нет. Остальные ${files(clean.length)} чистые.` : 'Пока проблем не найдено.';
  empty.textContent = message; empty.hidden = !message;
  $('#filterWrap').hidden = problems.length + clean.length < 2;
}
function setShowAll(value) {
  showAll = value; cleanLimit = CLEAN_PAGE;
  $('#onlyProblemsBtn').setAttribute('aria-pressed', String(!showAll));
  $('#onlyProblemsBtn').textContent = showAll ? 'Только проблемы' : 'Показать все';
  renderClean(); updateListChrome();
}
function applyQuery() {
  query = String($('#filter').value || '').trim().toLowerCase();
  for (const p of problems) p.element.hidden = !p.search.includes(query);
  cleanLimit = CLEAN_PAGE; renderClean(); updateListChrome();
}
function resetResults() {
  problems = []; clean = []; cleanRendered = 0; cleanMatches = 0; cleanLimit = CLEAN_PAGE; lastTotals = {files: 0, done: false};
  $('#scanList').replaceChildren(); $('#cleanList').replaceChildren();
}

function clamState(event) {
  const dot = $('#clamDot');
  if (event.clam) { dot.dataset.state = 'on'; $('#clamInfo').textContent = 'ClamAV готов'; }
  else if (event.clamLoading) { dot.dataset.state = 'loading'; $('#clamInfo').textContent = 'ClamAV загружается…'; }
  else { dot.dataset.state = 'off'; $('#clamInfo').textContent = 'ClamAV недоступен'; }
}
window.onNativeEvent = (event) => {
  try {
    if (event.event === 'auto') {
      $('#autoToggle').textContent = event.enabled ? 'Выключить' : 'Включить';
      $('#autoToggle').setAttribute('aria-pressed', String(event.enabled));
      $('#autoDot').dataset.state = event.enabled ? 'on' : 'off';
      $('#autoStatus').textContent = event.enabled ? 'Автопроверка включена' : 'Автопроверка выключена';
    } else if (event.event === 'config') {
      busy(false);
      $('#databaseCount').textContent = ru(event.signatures);
      $('#signatureInfo').textContent = '';
      if (event.chrome) document.documentElement.dataset.chrome = event.chrome;
      clamReady = !!event.clam; $('#modeClam').disabled = !clamReady;
      clamState(event);
      if (!configured) {
        configured = true;
        setMode('static'); setLoad(typeof navigator !== 'undefined' && navigator.hardwareConcurrency >= 8 ? 4 : 2);
      }
      if (event.clam && !modeTouched) setMode('clam');
      if (!event.clam && $('#mode').value === 'clam') setMode('static');
    } else if (event.event === 'notice') notice(event.message);
    else if (event.event === 'importing') { busy(true); $('#cancel').disabled = true; notice('Загружаем список…'); }
    else if (event.event === 'started') {
      busy(true); resetResults();
      $('#totalCount').textContent = '0'; $('#findingCount').textContent = '0'; $('#speedText').textContent = '';
      $('#scan').hidden = false; $('#notice').hidden = true;
      lastMode = $('#mode').value;
      $('#filter').value = ''; query = '';
      setShowAll(!!PREFS.all);
      verdict('scanning', 'Проверяем…', 'Можно свернуть окно — ответ появится здесь.');
      announce('Проверка началась.');
      $('#scanBar').classList.add('running');
    } else if (event.event === 'scan') {
      setText('#totalCount', ru(event.files));
      setText('#findingCount', ru(event.matches + event.reviews));
      for (const report of event.rows) addReport(report);
      lastTotals = {files: event.files, done: event.done};
      updateListChrome();
      const last = event.rows[event.rows.length - 1];
      if (last && !event.done) $('#currentFile').textContent = last.path;
      if (event.done) $('#currentFile').textContent = '';
      $('#speedText').textContent = `· ${bytes(event.bytes / Math.max(event.seconds, 0.001))}/с · ${duration(event.seconds)}`;
      $('#scanStats').textContent = event.errors || event.skipped ? `Не открылись: ${ru(event.errors)}. Пропущены ссылки и служебные файлы: ${ru(event.skipped)}.` : '';
      if (!event.done) {
        const found = event.matches + event.reviews;
        $('#verdictText').textContent = `Проверено ${files(event.files)} · ${duration(event.seconds)}${found ? ` · подозрительных: ${ru(found)}` : ''}`;
      } else { busy(false); $('#scanBar').classList.remove('running'); finalVerdict(event); }
    }
  } finally {
    // One update in flight: a slow/minimized renderer cannot accumulate result batches.
    if (event.event === 'scan') send('ack');
  }
};

for (const type of ['file', 'folder']) $('#' + (type === 'file' ? 'chooseFile' : 'chooseFolder')).addEventListener('click', () => send(`pick:${type}:${$('#mode').value}:${$('#workers').value}`));
for (const [target, id] of [['downloads', 'quickDownloads'], ['desktop', 'quickDesktop'], ['home', 'quickHome']])
  $('#' + id).addEventListener('click', () => send(`pick:${target}:${$('#mode').value}:${$('#workers').value}`));
$('#cancel').addEventListener('click', () => { send('cancel'); $('#cancel').disabled = true; $('#verdictText').textContent = 'Останавливаем…'; });
$('#clear').addEventListener('click', () => {
  if (running) return;
  resetResults(); $('#scan').hidden = true;
  verdict('idle', IDLE_TITLE, IDLE_TEXT);
});
$('#import').addEventListener('click', () => send('import'));
$('#filter').addEventListener('input', applyQuery);
$('#onlyProblemsBtn').addEventListener('click', () => setShowAll(!showAll));
$('#moreClean').addEventListener('click', () => { cleanLimit += CLEAN_PAGE; renderClean(); updateListChrome(); });
for (const [v, id] of Object.entries(MODES)) $('#' + id).addEventListener('click', () => { modeTouched = true; setMode(v); });
for (const [v, id] of Object.entries(LOADS)) $('#' + id).addEventListener('click', () => setLoad(v));
$('#autoToggle').addEventListener('click', () => send('auto-toggle'));
// Настройки — выпадающее меню справа сверху.
function menu(open) { $('#settings').hidden = !open; $('#settingsBtn').setAttribute('aria-expanded', String(open)); if (open) { setMode($('#mode').value); setLoad($('#workers').value); choose(THEMES, null, PREFS.theme); } }
$('#settingsBtn').addEventListener('click', (e) => { e?.stopPropagation?.(); menu($('#settings').hidden); });
window.toggleSettings = () => menu($('#settings').hidden);
if (typeof document.addEventListener === 'function') {
  document.addEventListener('click', (e) => { if (!$('#settings').hidden && !$('#settings').contains(e.target)) menu(false); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') menu(false);
    // Ctrl+F — к поиску по результатам.
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f' && !$('#scan').hidden && !$('#filterWrap').hidden) { e.preventDefault(); $('#filter').focus(); }
  });
}
for (const [v, id] of Object.entries(THEMES)) $('#' + id).addEventListener('click', () => { PREFS.theme = v; applyPrefs(); });
for (const [k, id] of Object.entries(SWITCHES)) $('#' + id).addEventListener('click', () => { PREFS[k] = !PREFS[k]; applyPrefs(); });
applyPrefs(); showLast();
send('ready');
