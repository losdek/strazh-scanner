const $ = (selector) => document.querySelector(selector);
let rows = [];
let running = false;
let received = 0;
let lastMode = 'static';
let modeTouched = false;
let configured = false;
let clamReady = false;
const controls = ['chooseFile', 'chooseFolder', 'quickDownloads', 'quickDesktop', 'quickHome', 'import', 'clear', 'modeHashes', 'modeStatic', 'w1', 'w2', 'w4'];
const MODES = {hashes: 'modeHashes', static: 'modeStatic', clam: 'modeClam'};
const LOADS = {1: 'w1', 2: 'w2', 4: 'w4'};
/* Кнопки-переключатели вместо выпадающих списков; бегунок плавно переезжает. */
function choose(group, ids, field, value) {
  const f = $(field); if (f) f.value = String(value);
  for (const [v, id] of Object.entries(ids)) $('#' + id).dataset.on = String(v === String(value));
  const target = $('#' + ids[value]);
  const thumb = target.parentElement?.querySelector?.('.thumb');
  if (thumb && target.offsetWidth) { thumb.style.width = target.offsetWidth + 'px'; thumb.style.transform = `translateX(${target.offsetLeft - 3}px)`; }
}
const setMode = (v) => choose('mode', MODES, '#mode', v);
const setLoad = (v) => choose('load', LOADS, '#workers', v);
function send(message) {
  const bridge = window.webkit?.messageHandlers?.scanner || window.chrome?.webview;
  if (!bridge) { notice('Откройте приложение через run.sh.'); return; }
  bridge.postMessage(message);
}
function notice(message) { $('#notice').hidden = false; $('#notice').textContent = message; }
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
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many);
}
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
  try { finishHooks(e); } catch {}
  const threats = e.matches, suspicious = e.reviews;
  const where = lastMode === 'clam' ? 'по базе Стража и базе ClamAV'
    : lastMode === 'static' ? 'по базе Стража и по признакам в содержимом'
    : 'по базе известных угроз Стража';
  if (e.cancelled) {
    verdict('partial', 'Остановлено', `Успели проверить ${e.files.toLocaleString('ru-RU')} ${plural(e.files, 'файл', 'файла', 'файлов')}.`);
  } else if (threats > 0) {
    verdict('threat', 'Найдены вирусы', `${threats.toLocaleString('ru-RU')} ${plural(threats, 'опасный файл', 'опасных файла', 'опасных файлов')}. Не открывайте ${plural(threats, 'его', 'их', 'их')} — лучше удалить.`);
  } else if (suspicious > 0) {
    verdict('review', 'Есть сомнительные файлы', `Вирусов нет, но ${suspicious.toLocaleString('ru-RU')} ${plural(suspicious, 'файл ведёт', 'файла ведут', 'файлов ведут')} себя странно. Открывайте, только если доверяете источнику.`);
  } else if (e.files === 0 && e.errors === 0) {
    verdict('partial', 'Пусто', 'Здесь нет файлов для проверки.');
  } else if (e.errors > 0) {
    verdict('partial', 'Проверено не всё', `Вирусов нет, но ${e.errors.toLocaleString('ru-RU')} ${plural(e.errors, 'файл', 'файла', 'файлов')} не удалось открыть.`);
  } else {
    verdict('safe', 'Вирусов не найдено', `${e.files.toLocaleString('ru-RU')} ${plural(e.files, 'файл', 'файла', 'файлов')} — всё чисто.`);
  }
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
  choose('theme', THEMES, '#themeValue', PREFS.theme);
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
  const what = {safe: 'чисто', threat: 'найдены вирусы', review: 'есть сомнительные', partial: 'не полностью'}[last.state] || '';
  $('#lastScan').textContent = `Последняя проверка: ${when} · ${last.files.toLocaleString('ru-RU')} ${plural(last.files, 'файл', 'файла', 'файлов')} · ${what}`;
}
const pressed = (el) => el.getAttribute ? el.getAttribute('aria-pressed') : el['aria-pressed'];
function finishHooks(e) {
  setTimeout(() => {
    const state = $('#verdict').dataset.state;
    if (state === 'threat') beep();
    if (!e.cancelled && e.files > 0) { store.set('strazh-last', JSON.stringify({when: Date.now(), state, files: e.files})); showLast(); }
  }, 0);
}
function applyFilter() {
  const filter = $('#filter'); const query = filter ? filter.value.toLowerCase() : '';
  const only = pressed($('#onlyProblemsBtn')) === 'true';
  for (const row of rows) row.element.hidden = !row.search.includes(query) || (only && !row.important);
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
function russian(text) {
  const dictionary = {'Data':'Данные','Windows executable':'Программа Windows','Linux executable':'Программа Linux','macOS executable':'Программа macOS','PDF':'Документ PDF','ZIP archive':'Архив ZIP','PNG image':'Изображение PNG','JPEG image':'Изображение JPEG','GIF image':'Изображение GIF','Script':'Сценарий','Text':'Текст','RAR archive':'Архив RAR','7-Zip archive':'Архив 7-Zip','Gzip archive':'Архив Gzip','Office document':'Документ Office','Empty':'Пустой файл','Java class/macOS binary':'Java / программа macOS','EICAR harmless antivirus test pattern':'Безопасный тестовый образец EICAR (проверка антивирусов)','ClamAV: no signature match (within daemon scan limits)':'ClamAV: угроз не найдено','File changed during scanning; scan it again':'Файл изменился во время проверки. Проверьте его ещё раз.','Not a regular file':'Это не обычный файл'};
  if (dictionary[text]) return dictionary[text];
  if (text.startsWith('Review: ')) { const label = text.slice(8); return 'Подозрительно: ' + (REVIEW[label] || label); }
  if (text.startsWith('ClamAV: ') && !text.startsWith('ClamAV: no')) return 'ClamAV нашёл угрозу: ' + text.slice(8);
  return text.replace('Hash intelligence:', 'Файл есть в базе угроз:').replace('Imported blocklist:', 'Файл есть в вашем списке:').replace('ClamAV incomplete:', 'ClamAV не смог завершить проверку:');
}
function append(report) {
  const li = document.createElement('li'); li.className = 'scan-row';
  li.dataset.tone = report.status === 'match' ? 'bad' : report.status;
  const top = document.createElement('div'); top.className = 'scan-row-top';
  const name = document.createElement('span'); name.className = 'scan-name'; name.textContent = report.path; name.title = report.path;
  const meta = document.createElement('span'); meta.className = 'scan-meta'; meta.textContent = `${russian(report.kind)} · ${bytes(report.size)}`;
  const badge = document.createElement('span'); badge.className = 'scan-badge';
  badge.textContent = ({match:'Угроза',review:'Подозрительный',unknown:'Чисто',empty:'Пустой файл',error:'Не проверен'})[report.status];
  top.append(name, meta, badge); li.append(top);
  if (report.hash && report.status !== 'unknown') {
    const hash = document.createElement('div'); hash.className = 'scan-hash'; hash.textContent = report.hash; hash.title = 'SHA-256 — выделите, чтобы скопировать'; li.append(hash);
  }
  const details = report.details.filter(d => report.status !== 'unknown' || !d.startsWith('ClamAV: no'));
  if (details.length) { const d = document.createElement('div'); d.className = 'scan-details'; d.textContent = details.map(russian).join('\n'); li.append(d); }
  const important = ['match','review','error'].includes(report.status);
  rows.push({element:li, important, search:(report.path + ' ' + report.hash).toLowerCase()});
  $('#scanList').append(li);
}
function clamState(event) {
  const dot = $('#clamDot');
  if (event.clam) {
    dot.dataset.state = 'on';
    $('#clamInfo').textContent = 'ClamAV готов';
  } else if (event.clamLoading) {
    dot.dataset.state = 'loading';
    $('#clamInfo').textContent = 'ClamAV загружается…';
  } else {
    dot.dataset.state = 'off';
    $('#clamInfo').textContent = 'ClamAV недоступен';
  }
}
window.onNativeEvent = (event) => {
  try {
    if (event.event === 'auto') {
      $('#autoToggle').textContent = event.enabled ? 'Выключить автопроверку' : 'Включить автопроверку';
      $('#autoToggle').setAttribute('aria-pressed', String(event.enabled));
      $('#autoDot').dataset.state = event.enabled ? 'on' : 'off';
      $('#autoStatus').textContent = event.enabled ? 'Включена' : 'Выключена';
    } else if (event.event === 'config') {
      busy(false);
      $('#databaseCount').textContent = event.signatures.toLocaleString('ru-RU');
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
      busy(true); $('#totalCount').textContent = '0'; $('#findingCount').textContent = '0'; received = 0; rows = []; $('#scanList').replaceChildren(); $('#scan').hidden = false; $('#notice').hidden = true;
      lastMode = $('#mode').value;
      $('#onlyProblemsBtn').setAttribute('aria-pressed', String(!PREFS.all)); $('#onlyProblemsBtn').textContent = PREFS.all ? 'Только проблемы' : 'Показать все';
      verdict('scanning', 'Проверяем…', 'Можно свернуть окно — ответ появится здесь.');
      $('#scanTitle').textContent = 'Результаты'; $('#scanBar').classList.add('running');
    } else if (event.event === 'scan') {
      setText('#totalCount', event.files.toLocaleString('ru-RU'));
      setText('#findingCount', (event.matches + event.reviews).toLocaleString('ru-RU'));
      for (const report of event.rows) { received++; append(report); }
      const last = event.rows[event.rows.length - 1];
      if (last && !event.done) $('#currentFile').textContent = last.path;
      if (event.done) $('#currentFile').textContent = '';
      applyFilter();
      const rate = `${bytes(event.bytes / Math.max(event.seconds, 0.001))}/с`;
      $('#speedText').textContent = `· ${rate}`;
      $('#scanTitle').textContent = 'Результаты';
      $('#scanStats').textContent = event.errors || event.skipped ? `Не открылись: ${event.errors}. Пропущены ссылки и служебные файлы: ${event.skipped}.` : '';
      if (!event.done) {
        const n = event.files.toLocaleString('ru-RU');
        $('#verdictText').textContent = `Проверено ${n} ${plural(event.files, 'файл', 'файла', 'файлов')}${event.matches + event.reviews ? ` · найдено подозрительного: ${event.matches + event.reviews}` : ''}`;
      } else { busy(false); $('#scanBar').classList.remove('running'); finalVerdict(event); }
    }
  } finally {
    // One update in flight: a slow/minimized renderer cannot accumulate result batches.
    if (event.event === 'scan') send('ack');
  }
};
for (const type of ['file','folder']) $('#' + (type === 'file' ? 'chooseFile' : 'chooseFolder')).addEventListener('click', () => send(`pick:${type}:${$('#mode').value}:${$('#workers').value}`));
$('#cancel').addEventListener('click', () => { send('cancel'); $('#cancel').disabled = true; $('#verdictText').textContent = 'Останавливаем…'; });
$('#clear').addEventListener('click', () => {
  if (running) return;
  rows = []; received = 0; $('#scanList').replaceChildren(); $('#scan').hidden = true;
  verdict('idle', 'Что проверим?', 'Файлы не запускаются и не покидают компьютер.');
});
$('#import').addEventListener('click', () => send('import'));
$('#filter')?.addEventListener('input', applyFilter);
$('#onlyProblemsBtn').addEventListener('click', () => { const on = pressed($('#onlyProblemsBtn')) !== 'true'; $('#onlyProblemsBtn').setAttribute('aria-pressed', String(on)); $('#onlyProblemsBtn').textContent = on ? 'Показать все' : 'Только проблемы'; applyFilter(); });
for (const [v, id] of Object.entries(MODES)) $('#' + id).addEventListener('click', () => { modeTouched = true; setMode(v); });
for (const [v, id] of Object.entries(LOADS)) $('#' + id).addEventListener('click', () => setLoad(v));
$('#autoToggle').addEventListener('click', () => send('auto-toggle'));
// Настройки — выпадающее меню справа сверху.
function menu(open) { $('#settings').hidden = !open; $('#settingsBtn').setAttribute('aria-expanded', String(open)); if (open) { setMode($('#mode').value); setLoad($('#workers').value); choose('theme', THEMES, '#themeValue', PREFS.theme); } }
$('#settingsBtn').addEventListener('click', (e) => { e?.stopPropagation?.(); menu($('#settings').hidden); });
window.toggleSettings = () => menu($('#settings').hidden);
if (typeof document.addEventListener === 'function') {
  document.addEventListener('click', (e) => { if (!$('#settings').hidden && !$('#settings').contains(e.target)) menu(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') menu(false); });
}
for (const [target, id] of [['downloads', 'quickDownloads'], ['desktop', 'quickDesktop'], ['home', 'quickHome']])
  $('#' + id).addEventListener('click', () => send(`pick:${target}:${$('#mode').value}:${$('#workers').value}`));
for (const [v, id] of Object.entries(THEMES)) $('#' + id).addEventListener('click', () => { PREFS.theme = v; applyPrefs(); });
for (const [k, id] of Object.entries(SWITCHES)) $('#' + id).addEventListener('click', () => { PREFS[k] = !PREFS[k]; applyPrefs(); });
applyPrefs(); showLast();
send('ready');
