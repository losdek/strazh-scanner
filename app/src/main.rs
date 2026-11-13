mod auto;
mod clamd;
mod gtk;
mod ui;
use gtk::*;
use scan_engine::{Config, Database, Mode};
use std::{
    cell::{Cell, RefCell},
    ffi::{CStr, CString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    ptr::null_mut,
    sync::{atomic::Ordering, mpsc, Arc},
};
use virustotal_local::{json, scan};
struct Ui {
    window: Widget,
    view: Widget,
    session: RefCell<Option<scan::Session>>,
    database: RefCell<Arc<Database>>,
    import: RefCell<Option<mpsc::Receiver<Result<Database, String>>>>,
    closing: Cell<bool>,
    dialog_open: Cell<bool>,
    pending: Cell<bool>,
    automatic: RefCell<Option<auto::Auto>>,
    auto_scan: Cell<bool>,
    clamd: RefCell<Option<clamd::Clamd>>,
    clam_ready: Cell<bool>,
}
/// A folder from ~/.config/user-dirs.dirs (e.g. ~/Загрузки on Russian systems), else a fallback.
fn user_dir(key: &str, fallback: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let configured = std::fs::read_to_string(config.join("user-dirs.dirs"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let value = line
                    .strip_prefix(key)?
                    .strip_prefix('=')?
                    .trim()
                    .trim_matches('"');
                let path = match value.strip_prefix("$HOME") {
                    Some(rest) => home.join(rest.trim_start_matches('/')),
                    None => PathBuf::from(value),
                };
                path.is_dir().then_some(path)
            })
        });
    configured.unwrap_or_else(|| home.join(fallback))
}
unsafe fn emit(ui: &Ui, event: &str) {
    if ui.closing.get() {
        return;
    }
    let script = CString::new(format!("window.onNativeEvent?.({event});")).unwrap();
    webkit_web_view_evaluate_javascript(
        ui.view,
        script.as_ptr(),
        -1,
        std::ptr::null(),
        std::ptr::null(),
        null_mut(),
        None,
        null_mut(),
    );
}
/// The settings button lives in the native title bar; it asks the page to open its menu.
unsafe extern "C" fn settings_clicked(_: Widget, data: Widget) {
    let ui = &*(data as *const Ui);
    if ui.closing.get() {
        return;
    }
    let script = c"window.toggleSettings?.();";
    webkit_web_view_evaluate_javascript(
        ui.view,
        script.as_ptr(),
        -1,
        std::ptr::null(),
        std::ptr::null(),
        null_mut(),
        None,
        null_mut(),
    );
}
unsafe fn notice(ui: &Ui, message: &str) {
    emit(
        ui,
        &format!(
            "{{\"event\":\"notice\",\"message\":{}}}",
            json::string(message)
        ),
    );
}
unsafe fn config(ui: &Ui) {
    emit(
        ui,
        &format!(
            "{{\"event\":\"config\",\"chrome\":\"native\",\"signatures\":{},\"clam\":{},\"clamLoading\":{}}}",
            ui.database.borrow().len(),
            ui.clam_ready.get(),
            !ui.clam_ready.get() && ui.clamd.borrow_mut().as_mut().is_some_and(|c| c.running())
        ),
    );
}
unsafe fn choose(ui: &Ui, folder: bool, multiple: bool) -> Vec<PathBuf> {
    if ui.dialog_open.replace(true) {
        return Vec::new();
    }
    let dialog = gtk_file_chooser_native_new(
        c"Выберите файл или папку".as_ptr(),
        ui.window,
        if folder { 2 } else { 0 },
        c"Выбрать".as_ptr(),
        c"Отмена".as_ptr(),
    );
    gtk_file_chooser_set_select_multiple(dialog, i32::from(multiple));
    let response = gtk_native_dialog_run(dialog);
    let mut paths = Vec::new();
    if response == -3 && !ui.closing.get() {
        let list = gtk_file_chooser_get_filenames(dialog);
        let mut next = list;
        while !next.is_null() {
            let raw = (*next).data;
            if !raw.is_null() {
                paths.push(PathBuf::from(std::ffi::OsStr::from_bytes(
                    CStr::from_ptr(raw.cast()).to_bytes(),
                )));
                g_free(raw);
            }
            next = (*next).next;
        }
        g_slist_free(list);
    }
    gtk_native_dialog_destroy(dialog);
    g_object_unref(dialog);
    ui.dialog_open.set(false);
    paths
}
unsafe extern "C" fn message(_: Widget, result: Widget, data: Widget) {
    let ui = &*(data as *const Ui);
    let raw = jsc_value_to_string(webkit_javascript_result_get_js_value(result));
    if raw.is_null() {
        return;
    }
    let command = CStr::from_ptr(raw).to_string_lossy().into_owned();
    g_free(raw.cast());
    if command == "auto-toggle" {
        if ui.automatic.borrow().is_some() {
            *ui.automatic.borrow_mut() = None;
            if ui.auto_scan.get() {
                if let Some(s) = ui.session.borrow().as_ref() {
                    s.cancel.store(true, Ordering::Relaxed);
                }
            }
            emit(ui, "{\"event\":\"auto\",\"enabled\":false}");
        } else {
            let root = user_dir("XDG_DOWNLOAD_DIR", "Downloads");
            if !root.is_dir() {
                notice(ui, "Папка «Загрузки» не найдена.");
                return;
            }
            match auto::Auto::start(root) {
                Ok(watcher) => {
                    *ui.automatic.borrow_mut() = Some(watcher);
                    emit(ui, "{\"event\":\"auto\",\"enabled\":true}");
                }
                Err(e) => notice(ui, &format!("Не удалось включить автопроверку: {e}")),
            }
        }
        return;
    }
    if command == "ack" {
        ui.pending.set(false);
        return;
    }
    if command == "ready" {
        config(ui);
        return;
    }
    if command == "cancel" {
        if let Some(s) = ui.session.borrow().as_ref() {
            s.cancel.store(true, Ordering::Relaxed);
        }
        return;
    }
    if ui.session.borrow().is_some() || ui.import.borrow().is_some() {
        notice(ui, "Дождитесь завершения текущей операции.");
        return;
    }
    if command == "import" {
        let paths = choose(ui, false, false);
        if let Some(path) = paths.into_iter().next() {
            let (tx, rx) = mpsc::sync_channel(1);
            *ui.import.borrow_mut() = Some(rx);
            emit(ui, "{\"event\":\"importing\"}");
            std::thread::spawn(move || {
                let _ = tx.send(scan_engine::load_database(&path).map_err(|e| e.to_string()));
            });
        }
        return;
    }
    let fields: Vec<_> = command.split(':').collect();
    if fields.len() != 4 || fields[0] != "pick" {
        return;
    }
    // Quick targets scan a known folder without a dialog.
    let quick = match fields[1] {
        "downloads" => Some(user_dir("XDG_DOWNLOAD_DIR", "Downloads")),
        "desktop" => Some(user_dir("XDG_DESKTOP_DIR", "Desktop")),
        "home" => std::env::var_os("HOME").map(PathBuf::from),
        "file" | "folder" => None,
        _ => return,
    };
    let folder = fields[1] == "folder";
    let Some(mode) = Mode::parse(fields[2]) else {
        return;
    };
    let Ok(workers) = fields[3].parse::<usize>() else {
        return;
    };
    if !(1..=4).contains(&workers) {
        return;
    }
    let config = Config {
        mode,
        database: ui.database.borrow().clone(),
        clam_socket: scan_engine::detect_clam(),
    };
    if mode == Mode::Clam && config.clam_socket.is_none() {
        notice(ui,"ClamAV не запущен. Выберите обычную проверку или запустите службу clamd с базой сигнатур.");
        return;
    }
    let paths = match quick {
        Some(dir) if dir.is_dir() => vec![dir],
        Some(dir) => {
            notice(ui, &format!("Папка не найдена: {}", dir.display()));
            return;
        }
        None => choose(ui, folder, !folder),
    };
    if paths.is_empty() || ui.closing.get() {
        return;
    }
    match scan::start(paths, config, workers) {
        Ok(session) => {
            *ui.session.borrow_mut() = Some(session);
            emit(ui, "{\"event\":\"started\"}");
        }
        Err(e) => notice(ui, &e.to_string()),
    }
}
unsafe extern "C" fn tick(data: Widget) -> i32 {
    let ui = &*(data as *const Ui);
    if ui.closing.get() {
        return 1;
    }
    let loaded = ui
        .import
        .borrow()
        .as_ref()
        .and_then(|rx| rx.try_recv().ok());
    if let Some(result) = loaded {
        *ui.import.borrow_mut() = None;
        match result {
            Ok(db) => {
                let mut merged = (*scan_engine::bundled_database()).clone();
                merged.extend(db);
                *ui.database.borrow_mut() = Arc::new(merged);
                config(ui);
                notice(
                    ui,
                    "Список загружен. Он будет использован при следующих проверках.",
                );
            }
            Err(e) => {
                config(ui);
                notice(
                    ui,
                    &format!("Ошибка загрузки: {e}. Предыдущий список сохранён."),
                );
            }
        }
    }
    let clam_now = scan_engine::detect_clam().is_some();
    if clam_now != ui.clam_ready.replace(clam_now) {
        config(ui);
    }
    if ui.pending.get() {
        return 1;
    }
    if ui.session.borrow().is_none() && ui.import.borrow().is_none() {
        let files = ui
            .automatic
            .borrow()
            .as_ref()
            .and_then(|a| a.files.try_recv().ok());
        if let Some(files) = files {
            let cfg = Config {
                database: ui.database.borrow().clone(),
                mode: if ui.clam_ready.get() {
                    Mode::Clam
                } else {
                    Mode::Static
                },
                ..Config::default()
            };
            match scan::start(files, cfg, 2) {
                Ok(session) => {
                    *ui.session.borrow_mut() = Some(session);
                    ui.auto_scan.set(true);
                    emit(ui, "{\"event\":\"started\"}");
                }
                Err(e) => notice(ui, &format!("Ошибка автопроверки: {e}")),
            }
        }
    }
    let mut finished = false;
    {
        let session = ui.session.borrow();
        if let Some(session) = session.as_ref() {
            let mut rows = Vec::new();
            for _ in 0..64 {
                match session.events.try_recv() {
                    Ok(scan::Event::Row(r)) => rows.push(json::report(&r)),
                    Ok(scan::Event::Done) => {
                        finished = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        finished = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }
            ui.pending.set(true);
            emit(ui, &json::snapshot(session, finished, &rows));
        }
    }
    if finished {
        *ui.session.borrow_mut() = None;
        ui.auto_scan.set(false);
    }
    1
}
unsafe extern "C" fn close(_: Widget, data: Widget) {
    let ui = &*(data as *const Ui);
    ui.closing.set(true);
    if let Some(s) = ui.session.borrow().as_ref() {
        s.cancel.store(true, Ordering::Relaxed);
    }
    gtk_main_quit();
}
fn main() {
    if std::env::args_os().len() > 1 {
        virustotal_local::cli::main();
    }
    // Start loading the ClamAV database (~10 s) before GTK and WebKit spend time starting up.
    let clamd = clamd::start();
    unsafe {
        if gtk_init_check(null_mut(), null_mut()) == 0 {
            eprintln!("Cannot access desktop display. Run ./run.sh from your desktop terminal, or use app/vt-scan for file scanning.");
            drop(clamd); // process::exit skips destructors; stop clamd first.
            std::process::exit(1);
        }
        let window = gtk_window_new(0);
        gtk_window_set_title(window, c"Страж".as_ptr());
        gtk_window_set_default_size(window, 1440, 900);
        // Title bar merged with the app: brand on the left, settings on the right, system window buttons.
        let header = gtk_header_bar_new();
        gtk_header_bar_set_show_close_button(header, 1);
        gtk_header_bar_set_title(header, c"Страж".as_ptr());
        let settings = gtk_button_new_from_icon_name(c"preferences-system-symbolic".as_ptr(), 2);
        gtk_widget_set_tooltip_text(settings, c"Настройки".as_ptr());
        gtk_header_bar_pack_end(header, settings);
        gtk_window_set_titlebar(window, header);
        let view = webkit_web_view_new();
        gtk_container_add(window, view);
        webkit_web_context_set_cache_model(webkit_web_view_get_context(view), 0);
        webkit_settings_set_enable_page_cache(webkit_web_view_get_settings(view), 0);
        let ui = Box::new(Ui {
            window,
            view,
            session: RefCell::new(None),
            database: RefCell::new(scan_engine::bundled_database()),
            import: RefCell::new(None),
            closing: Cell::new(false),
            dialog_open: Cell::new(false),
            pending: Cell::new(false),
            automatic: RefCell::new(None),
            auto_scan: Cell::new(false),
            clamd: RefCell::new(clamd),
            clam_ready: Cell::new(false),
        });
        let data = (&*ui as *const Ui).cast_mut().cast();
        let manager = webkit_web_view_get_user_content_manager(view);
        g_signal_connect_data(
            manager,
            c"script-message-received::scanner".as_ptr(),
            std::mem::transmute::<
                unsafe extern "C" fn(Widget, Widget, Widget),
                unsafe extern "C" fn(),
            >(message),
            data,
            None,
            0,
        );
        if webkit_user_content_manager_register_script_message_handler(manager, c"scanner".as_ptr())
            == 0
        {
            eprintln!("Cannot initialize native scanner bridge");
            std::process::exit(1);
        }
        g_signal_connect_data(
            window,
            c"destroy".as_ptr(),
            std::mem::transmute::<unsafe extern "C" fn(Widget, Widget), unsafe extern "C" fn()>(
                close,
            ),
            data,
            None,
            0,
        );
        g_signal_connect_data(
            settings,
            c"clicked".as_ptr(),
            std::mem::transmute::<unsafe extern "C" fn(Widget, Widget), unsafe extern "C" fn()>(
                settings_clicked,
            ),
            data,
            None,
            0,
        );
        let timer = g_timeout_add(150, tick, data);
        let html = CString::new(ui::html()).unwrap();
        webkit_web_view_load_html(view, html.as_ptr(), c"file:///virustotal-local/".as_ptr());
        gtk_widget_show_all(window);
        gtk_main();
        g_source_remove(timer);
    }
}
