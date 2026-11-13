//! Minimal bindings to the installed GTK and WebKit libraries; UI thread only.
use std::ffi::{c_char, c_int, c_void};
pub type Widget = *mut c_void;
#[link(name = "gtk-3")]
extern "C" {
    pub fn gtk_init_check(argc: *mut c_int, argv: *mut *mut *mut c_char) -> c_int;
    pub fn gtk_main();
    pub fn gtk_main_quit();
    pub fn gtk_window_new(kind: c_int) -> Widget;
    pub fn gtk_window_set_title(w: Widget, title: *const c_char);
    pub fn gtk_window_set_default_size(w: Widget, width: c_int, height: c_int);
    pub fn gtk_container_add(w: Widget, child: Widget);
    pub fn gtk_widget_show_all(w: Widget);
    pub fn gtk_window_set_titlebar(w: Widget, titlebar: Widget);
    pub fn gtk_header_bar_new() -> Widget;
    pub fn gtk_header_bar_set_show_close_button(w: Widget, show: c_int);
    pub fn gtk_header_bar_set_title(w: Widget, title: *const c_char);
    pub fn gtk_header_bar_pack_end(bar: Widget, child: Widget);
    pub fn gtk_button_new_from_icon_name(name: *const c_char, size: c_int) -> Widget;
    pub fn gtk_widget_set_tooltip_text(w: Widget, text: *const c_char);
}
#[link(name = "gobject-2.0")]
extern "C" {
    pub fn g_signal_connect_data(
        w: Widget,
        signal: *const c_char,
        callback: unsafe extern "C" fn(),
        data: Widget,
        destroy: Option<unsafe extern "C" fn(Widget, Widget)>,
        flags: u32,
    ) -> usize;
}
#[link(name = "webkit2gtk-4.1")]
extern "C" {
    pub fn webkit_web_view_new() -> Widget;
    pub fn webkit_web_view_load_html(w: Widget, html: *const c_char, base_uri: *const c_char);
}
#[repr(C)]
pub struct SList {
    pub data: Widget,
    pub next: *mut SList,
}
#[link(name = "gtk-3")]
extern "C" {
    pub fn gtk_file_chooser_native_new(
        title: *const c_char,
        parent: Widget,
        action: c_int,
        accept: *const c_char,
        cancel: *const c_char,
    ) -> Widget;
    pub fn gtk_native_dialog_run(dialog: Widget) -> c_int;
    pub fn gtk_native_dialog_destroy(dialog: Widget);
    pub fn gtk_file_chooser_set_select_multiple(dialog: Widget, multiple: c_int);
    pub fn gtk_file_chooser_get_filenames(dialog: Widget) -> *mut SList;
}
#[link(name = "glib-2.0")]
extern "C" {
    pub fn g_free(data: Widget);
    pub fn g_slist_free(list: *mut SList);
    pub fn g_timeout_add(
        interval: u32,
        callback: unsafe extern "C" fn(Widget) -> c_int,
        data: Widget,
    ) -> u32;
    pub fn g_source_remove(source: u32) -> c_int;
}
#[link(name = "gobject-2.0")]
extern "C" {
    pub fn g_object_unref(object: Widget);
}
#[link(name = "webkit2gtk-4.1")]
extern "C" {
    pub fn webkit_web_view_get_user_content_manager(view: Widget) -> Widget;
    pub fn webkit_user_content_manager_register_script_message_handler(
        manager: Widget,
        name: *const c_char,
    ) -> c_int;
    pub fn webkit_javascript_result_get_js_value(result: Widget) -> Widget;
    pub fn webkit_web_view_evaluate_javascript(
        view: Widget,
        script: *const c_char,
        length: isize,
        world: *const c_char,
        source: *const c_char,
        cancellable: Widget,
        callback: Option<unsafe extern "C" fn(Widget, Widget, Widget)>,
        data: Widget,
    );
    pub fn webkit_web_view_get_context(view: Widget) -> Widget;
    pub fn webkit_web_context_set_cache_model(context: Widget, model: c_int);
    pub fn webkit_web_view_get_settings(view: Widget) -> Widget;
    pub fn webkit_settings_set_enable_page_cache(settings: Widget, enabled: c_int);
}
#[link(name = "javascriptcoregtk-4.1")]
extern "C" {
    pub fn jsc_value_to_string(value: Widget) -> *mut c_char;
}
