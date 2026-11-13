using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Strazh;
static class Program {
    [STAThread] static void Main() { ApplicationConfiguration.Initialize(); Application.Run(new ScannerWindow()); }
}
sealed class ScannerWindow : Form {
    readonly WebView2 web = new() { Dock = DockStyle.Fill };
    readonly System.Windows.Forms.Timer timer = new() { Interval = 3000 };
    readonly Dictionary<string, (long size, DateTime modified, DateTime stable, bool scanned)> tracked = new();
    readonly string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Strazh");
    Process? scan;
    // Bundled ClamAV: clamd.exe listens on 127.0.0.1:3311 while the window is open.
    Process? clamd;
    bool clamReady;
    readonly System.Windows.Forms.Timer clamTimer = new() { Interval = 1000 };
    static readonly string ClamDir = Path.Combine(AppContext.BaseDirectory, "clamav");
    bool automatic, busy, cancelled, closing, autoScanning;
    string? signatures;
    long count, bytes, matches, reviews, errors, skipped;
    readonly Stopwatch elapsed = new();
    string Downloads {
        get {
            using var folders = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            var configured = folders?.GetValue("{374DE290-123F-4565-9164-39C4925E467B}") as string;
            return string.IsNullOrWhiteSpace(configured) ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads") : Environment.ExpandEnvironmentVariables(configured);
        }
    }
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    /// Windows 11: colour the system title bar like the app frame so the two read as one surface.
    void TintTitleBar() {
        try {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            bool dark = (key?.GetValue("AppsUseLightTheme") as int?) == 0;
            int immersive = dark ? 1 : 0, caption = dark ? 0x0036261D : 0x00F0E6DF, text = dark ? 0x00EFEBE9 : 0x001F1C1A;
            DwmSetWindowAttribute(Handle, 20, ref immersive, 4);
            DwmSetWindowAttribute(Handle, 35, ref caption, 4);
            DwmSetWindowAttribute(Handle, 36, ref text, 4);
            BackColor = dark ? Color.FromArgb(0x1D, 0x26, 0x36) : Color.FromArgb(0xDF, 0xE6, 0xF0);
        } catch { }
    }
    static string Resource(string name) { using var reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream(name)!); return reader.ReadToEnd(); }
    public ScannerWindow() {
        Text = "Страж"; HandleCreated += (_, _) => TintTitleBar(); Width = 1440; Height = 900; MinimumSize = new Size(750, 650);
        StartClamd(); // the database takes ~10 s to load; start before WebView2.
        clamTimer.Tick += async (_, _) => { var ready = await Task.Run(ClamAlive); if (ready != clamReady) { clamReady = ready; await Config(); } };
        clamTimer.Start();
        Controls.Add(web); Shown += async (_, _) => { try { await Initialize(); } catch(Exception e) { MessageBox.Show(this, "Не удалось запустить интерфейс. Переустановите Страж, чтобы восстановить WebView2.\n" + e.Message); } };
        FormClosing += (_, _) => { closing = true; timer.Stop(); clamTimer.Stop(); Stop(); StopClamd(); };
        timer.Tick += async (_, _) => await Watch();
    }
    static bool ClamAlive() {
        try {
            using var client = new System.Net.Sockets.TcpClient();
            if (!client.ConnectAsync("127.0.0.1", 3311).Wait(300)) return false;
            using var stream = client.GetStream();
            stream.Write("zPING\0"u8);
            stream.ReadTimeout = 500;
            var buffer = new byte[16];
            var n = stream.Read(buffer, 0, buffer.Length);
            return System.Text.Encoding.ASCII.GetString(buffer, 0, n).StartsWith("PONG");
        } catch { return false; }
    }
    void StartClamd() {
        try {
            var exe = Path.Combine(ClamDir, "clamd.exe");
            var db = Path.Combine(ClamDir, "db");
            if (!File.Exists(exe) || !Directory.Exists(db) || ClamAlive()) return;
            var spool = Path.Combine(data, "clamd-tmp");
            Directory.CreateDirectory(spool);
            var config = Path.Combine(data, "clamd.conf");
            File.WriteAllText(config, $"DatabaseDirectory {db}\nTCPSocket 3311\nTCPAddr 127.0.0.1\nForeground yes\nTemporaryDirectory {spool}\n" +
                "StreamMaxLength 4G\nMaxFileSize 0\nMaxScanSize 0\nMaxRecursion 64\nMaxFiles 0\nMaxThreads 4\nSelfCheck 3600\n");
            RefreshDatabase(db);
            var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = ClamDir };
            info.ArgumentList.Add("--config-file=" + config);
            clamd = Process.Start(info);
        } catch { clamd = null; }
    }
    void RefreshDatabase(string db) {
        // Quiet background update when the bundled database is more than a day old; offline is fine.
        try {
            var exe = Path.Combine(ClamDir, "freshclam.exe");
            var newest = Directory.EnumerateFiles(db).Where(f => f.EndsWith(".cvd") || f.EndsWith(".cld")).Select(File.GetLastWriteTimeUtc).DefaultIfEmpty(DateTime.MinValue).Max();
            if (!File.Exists(exe) || DateTime.UtcNow - newest < TimeSpan.FromDays(1)) return;
            var config = Path.Combine(data, "freshclam.conf");
            File.WriteAllText(config, $"DatabaseDirectory {db}\nDatabaseMirror database.clamav.net\nConnectTimeout 10\nReceiveTimeout 30\n");
            var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = ClamDir };
            info.ArgumentList.Add("--config-file=" + config); info.ArgumentList.Add("--quiet");
            Process.Start(info)?.Dispose();
        } catch { }
    }
    void StopClamd() { try { if (clamd is { HasExited: false }) clamd.Kill(true); } catch { } clamd?.Dispose(); clamd = null; }
    async Task Initialize() {
        Directory.CreateDirectory(data);
        var saved = Path.Combine(data, "custom-hashes.txt");
        if (File.Exists(saved)) signatures = saved;
        var environment = await CoreWebView2Environment.CreateAsync(null, Path.Combine(data, "WebView2"));
        await web.EnsureCoreWebView2Async(environment);
        web.CoreWebView2.Settings.AreDevToolsEnabled = false;
        web.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        web.CoreWebView2.NewWindowRequested += (_, e) => e.Handled = true;
        web.CoreWebView2.NavigationStarting += (_, e) => { if (!e.Uri.StartsWith("about:blank", StringComparison.OrdinalIgnoreCase)) e.Cancel = true; };
        web.CoreWebView2.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
        web.CoreWebView2.WebMessageReceived += async (_, e) => {
            try { await Command(e.TryGetWebMessageAsString()); } catch(Exception ex) { await Notice(ex.Message); }
        };
        var html = Resource("ui.html").Replace("<!--STYLES-->", "<style>"+Resource("ui.css")+"</style>")
            .Replace("<!--SCRIPTS-->", "<script>"+Resource("ui.js")+"</script>")
            .Replace("~/Downloads", "Downloads");
        web.CoreWebView2.NavigateToString(html);
    }
    async Task Emit(object value) { if (!closing && web.CoreWebView2 != null) await web.ExecuteScriptAsync("window.onNativeEvent?.(" + JsonSerializer.Serialize(value) + ");"); }
    Task Notice(string text) => Emit(new { @event = "notice", message = text });
    async Task Config() {
        var hashes = Resource("hashes.txt").Split('\n').Where(l => !l.StartsWith('#') && l.Length >= 64).Select(l => l[..64]).ToHashSet();
        if (signatures != null) foreach(var line in File.ReadLines(signatures)) if (line.Length >= 64 && !line.StartsWith('#')) hashes.Add(line[..64]);
        bool loading = !clamReady && clamd is { HasExited: false };
        await Emit(new { @event="config", signatures=hashes.Count, clam=clamReady, clamLoading=loading });
    }
    async Task Command(string command) {
        if (command == "ack") return;
        if (command == "ready") { await Config(); return; }
        if (command == "cancel") { Stop(); return; }
        if (command == "auto-toggle") {
            automatic = !automatic;
            if (automatic) { timer.Start(); } else { timer.Stop(); if (autoScanning) Stop(); }
            await Emit(new { @event="auto", enabled=automatic }); return;
        }
        if (busy) { await Notice("Дождитесь завершения проверки."); return; }
        if (command == "import") {
            using var dialog = new OpenFileDialog { Title="Добавить список SHA-256", Filter="Текстовый список|*.txt|Все файлы|*.*" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            // Validate every line before replacing the current list.
            int lines = 0;
            foreach (var raw in File.ReadLines(dialog.FileName)) {
                var line=raw.Trim(); if (line.Length==0 || line.StartsWith('#')) continue;
                if (++lines<0 || raw.Length>4096 || line.Length<64 || !line[..64].All(Uri.IsHexDigit) || (line.Length>64 && !char.IsWhiteSpace(line[64]))) throw new IOException("Неверный формат списка SHA-256.");
            }
            signatures=Path.Combine(data,"custom-hashes.txt"); File.Copy(dialog.FileName,signatures,true);
            await Config(); return;
        }
        var parts=command.Split(':');
        if(parts.Length!=4 || parts[0]!="pick" || !new[]{"hashes","static","clam"}.Contains(parts[2]) || !int.TryParse(parts[3],out var workers) || workers<1 || workers>4) return;
        string[] paths;
        if(parts[1]=="file") { using var dialog=new OpenFileDialog{Multiselect=true,Title="Выберите файлы"}; if(dialog.ShowDialog(this)!=DialogResult.OK)return; paths=dialog.FileNames; }
        else if(parts[1]=="folder") { using var dialog=new FolderBrowserDialog{Description="Выберите папку"}; if(dialog.ShowDialog(this)!=DialogResult.OK)return; paths=[dialog.SelectedPath]; }
        else {
            // Quick targets from the main screen: no dialog.
            var dir = parts[1] switch {
                "downloads" => Downloads,
                "desktop" => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                "home" => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                _ => null };
            if (dir == null) return;
            if (!Directory.Exists(dir)) { await Notice("Папка не найдена: " + dir); return; }
            paths=[dir];
        }
        if(parts[2]=="clam" && !clamReady) { await Notice("ClamAV ещё загружается. Подождите несколько секунд."); return; }
        await Scan(paths,parts[2],workers);
    }
    void Stop() { cancelled=true; try { if(scan is {HasExited:false}) scan.Kill(true); } catch(InvalidOperationException){} }
    async Task Snapshot(object[] rows, bool done, int workers) => await Emit(new { @event="scan",done,cancelled,files=count,bytes,matches,reviews,errors,skipped,seconds=elapsed.Elapsed.TotalSeconds,workers,rows });
    async Task Scan(string[] paths,string mode,int workers) {
        if(busy || closing)return; busy=true;cancelled=false;count=bytes=matches=reviews=errors=skipped=0;elapsed.Restart();
        await Emit(new { @event="started" });
        try {
            var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"vt-scan.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=System.Text.Encoding.UTF8,StandardErrorEncoding=System.Text.Encoding.UTF8};
            foreach(var arg in new[]{"--mode",mode,"--workers",workers.ToString()}) info.ArgumentList.Add(arg);
            if(signatures!=null){info.ArgumentList.Add("--signatures");info.ArgumentList.Add(signatures);}
            info.ArgumentList.Add("--");foreach(var path in paths)info.ArgumentList.Add(path);
            scan=Process.Start(info) ?? throw new IOException("Не удалось запустить Rust-сканер.");
            var stderr=scan.StandardError.ReadToEndAsync();
            var batch=new List<object>(32);
            bool completed=false;
            while(await scan.StandardOutput.ReadLineAsync() is string line) {
                using var doc=JsonDocument.Parse(line);var row=doc.RootElement;
                if(row.TryGetProperty("event",out _)) {
                    if(batch.Count>0){await Snapshot(batch.ToArray(),false,workers);batch.Clear();}
                    completed=true;
                    count=row.GetProperty("files").GetInt64();bytes=row.GetProperty("bytes").GetInt64();matches=row.GetProperty("matches").GetInt64();reviews=row.GetProperty("reviews").GetInt64();errors=row.GetProperty("errors").GetInt64();skipped=row.GetProperty("skipped").GetInt64();
                    continue;
                }
                count++;bytes+=row.GetProperty("size").GetInt64();
                switch(row.GetProperty("status").GetString()){case "match":matches++;break;case "review":reviews++;break;}
                if(row.GetProperty("incomplete").GetBoolean())errors++;
                batch.Add(row.Clone());
                if(batch.Count>=32){await Snapshot(batch.ToArray(),false,workers);batch.Clear();}
            }
            await scan.WaitForExitAsync();
            if(batch.Count>0)await Snapshot(batch.ToArray(),false,workers);
            var error=await stderr;
            if(!cancelled && (!completed || scan.ExitCode is < 0 or > 2)) throw new IOException("Сканер завершился без полного результата. " + error);
            if(scan.ExitCode==2&&!cancelled) { if(errors==0)errors++; if(!string.IsNullOrWhiteSpace(error))await Notice(error); }
        } catch(Exception e) {errors++; await Notice("Ошибка проверки: "+e.Message);}
        finally {elapsed.Stop();await Snapshot([],true,workers);scan?.Dispose();scan=null;busy=false;}
    }
    async Task Watch() {
        if(busy||!automatic||closing)return;
        busy=true;
        try {
            var ready=await Task.Run(()=> {
                var result=new List<string>();var present=new HashSet<string>();
                var downloads=Downloads;
                if(!Directory.Exists(downloads))return result;
                var options=new EnumerationOptions{RecurseSubdirectories=true,IgnoreInaccessible=true,AttributesToSkip=FileAttributes.ReparsePoint,MaxRecursionDepth=32};
                foreach(var path in Directory.EnumerateFiles(downloads,"*",options).Take(10000)) {
                    if(new[]{".part",".tmp",".crdownload",".!qb",".download",".aria2"}.Any(s=>path.EndsWith(s,StringComparison.OrdinalIgnoreCase)) || File.Exists(path+".aria2"))continue;
                    try { var f=new FileInfo(path);present.Add(path);
                        if(!tracked.TryGetValue(path,out var old)||old.size!=f.Length||old.modified!=f.LastWriteTimeUtc)tracked[path]=(f.Length,f.LastWriteTimeUtc,DateTime.UtcNow,false);
                        else if(!old.scanned&&(DateTime.UtcNow-old.stable).TotalSeconds>=10&&result.Count<32)result.Add(path);
                    }catch(IOException){}catch(UnauthorizedAccessException){}
                }
                foreach(var key in tracked.Keys.Where(k=>!present.Contains(k)).ToArray())tracked.Remove(key);
                return result;
            });
            busy=false;
            if(!automatic||closing)return;
            if(ready.Count>0){autoScanning=true;await Scan(ready.ToArray(),clamReady?"clam":"static",2);if(!cancelled&&errors==0)foreach(var path in ready)if(tracked.TryGetValue(path,out var value))tracked[path]=(value.size,value.modified,value.stable,true);}
        } catch(Exception e){await Notice("Автопроверка: "+e.Message);} finally {busy=false;autoScanning=false;}
    }
}
