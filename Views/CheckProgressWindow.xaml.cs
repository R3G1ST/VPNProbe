using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using VPNProbe.Models;
using VPNProbe.Services;

namespace VPNProbe.Views;

public partial class CheckProgressWindow : Window
{
    private readonly ObservableCollection<ServerRow> _rows = new();
    private CancellationTokenSource? _cts;
    private int _done, _ok, _fail, _total;
    private readonly Stopwatch _sw = new();

    public List<CheckResultDisplay> Results { get; } = new();

    public CheckProgressWindow()
    {
        InitializeComponent();
        ServerGrid.ItemsSource = _rows;
    }

    public async Task RunCheckAsync(string url, bool checkPing, bool checkPortTls, bool checkProxy, bool checkDpi)
    {
        _cts = new CancellationTokenSource();
        List<ServerInfo> servers = new();

        try
        {
            if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                var sub = await SubscriptionParser.FetchAndParse(url);
                if (sub.IsEmpty) { StatusText.Text = $"Ошибка: {sub.Error}"; return; }
                servers = sub.Servers;
            }
            else
            {
                servers = SubscriptionParser.ParseFromText(url);
            }
        }
        catch (Exception ex) { StatusText.Text = $"Ошибка: {ex.Message}"; return; }

        _total = servers.Count;
        TitleText.Text = $"Проверка серверов — {servers.Count} шт.";
        StatusText.Text = $"Проверяю {servers.Count} серверов...";
        _sw.Start();

        foreach (var s in servers)
            _rows.Add(new ServerRow { Name = s.DisplayName, StatusIcon = "○" });

        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = _cts.Token };

        await Parallel.ForEachAsync(Enumerable.Range(0, servers.Count), parallelOptions, async (idx, ct) =>
        {
            if (ct.IsCancellationRequested) return;
            var server = servers[idx];
            var row = _rows[idx];

            var display = new CheckResultDisplay { Server = server };

            try
            {
                using var serverCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                serverCts.CancelAfter(TimeSpan.FromSeconds(45));

                if (checkPing)
                {
                    var ping = await PingChecker.CheckAsync(server, serverCts.Token);
                    display.PingMs = ping.PingMs;
                    display.PingOk = ping.PingOk;
                    display.PingChecked = true;
                    TryInvoke(() => row.PingText = ping.PingOk ? $"{ping.PingMs}ms" : "—");
                }

                if (checkPortTls)
                {
                    var portTls = await PortTlsChecker.CheckAsync(server, serverCts.Token);
                    display.PortOpen = portTls.PortOpen;
                    display.TlsOk = portTls.TlsOk;
                    display.TlsExpiry = portTls.TlsExpiry;
                    if (portTls.Error != "") display.Error = portTls.Error;
                    TryInvoke(() =>
                    {
                        row.PortText = portTls.PortOpen ? "✓" : "✗";
                        row.TlsText = portTls.TlsOk ? "✓" : "✗";
                    });
                }

                if (checkProxy && display.PortOpen)
                {
                    var proxy = await ProxyChecker.CheckAsync(server, serverCts.Token);
                    display.ProxyOk = proxy.ProxyOk;
                    display.ProxyIp = proxy.ProxyIp;
                    if (proxy.Error != "") display.Error = proxy.Error;
                    TryInvoke(() =>
                    {
                        row.ProxyText = proxy.ProxyOk ? "✓" : "✗";
                        row.ProxyIp = proxy.ProxyIp;
                        if (!string.IsNullOrEmpty(proxy.Error)) row.Error = proxy.Error;
                    });

                    // Deep check: speed + stability + grade
                    if (proxy.ProxyOk)
                    {
                        var deep = await DeepCheckService.RunAllChecks(server, serverCts.Token);
                        display.DeepResult = deep;
                        TryInvoke(() =>
                        {
                            row.SpeedText = deep.SpeedMbps > 0 ? $"{deep.SpeedMbps:F1}Mbps" : "—";
                            row.LossText = deep.PacketLossPct > 0 ? $"{deep.PacketLossPct:F0}%" : "0%";
                            row.GradeText = deep.Grade;
                            if (deep.ExitIp != "") row.ProxyIp = deep.ExitIp;
                        });
                    }
                }

                var isOk = display.ProxyOk && (!display.PingChecked || display.PingOk);
                if (isOk) Interlocked.Increment(ref _ok); else Interlocked.Increment(ref _fail);
            }
            catch { Interlocked.Increment(ref _fail); }

            var progress = Interlocked.Increment(ref _done);
            Results.Add(display);

            TryInvoke(() =>
            {
                var isOkRow = display.ProxyOk && (!display.PingChecked || display.PingOk);
                row.StatusIcon = isOkRow ? "✓" : "✗";
                if (!string.IsNullOrEmpty(display.Error) && string.IsNullOrEmpty(row.Error))
                    row.Error = display.Error;

                OkCount.Text = $"OK: {_ok}";
                FailCount.Text = $"Fail: {_fail}";
                TotalCount.Text = $"{_done}/{_total}";
                ProgressBar.Value = (double)_done / _total * 100;

                var elapsed = _sw.Elapsed;
                var remaining = _total - _done;
                var eta = remaining > 0 && _done > 0
                    ? TimeSpan.FromTicks(elapsed.Ticks / _done * remaining)
                    : TimeSpan.Zero;
                var etaStr = eta.TotalMinutes >= 1
                    ? $"{(int)eta.TotalMinutes}m {eta.Seconds:D2}s"
                    : $"{(int)eta.TotalSeconds}s";
                StatusText.Text = $"{_done}/{_total} — {server.Name}  |  ETA {etaStr}";
            });
        });

        TryInvoke(() =>
        {
            BtnStop.Visibility = Visibility.Collapsed;
            BtnDone.Visibility = Visibility.Visible;
            TitleText.Text = "Проверка завершена";
            StatusText.Text = $"Завершено — OK: {_ok}, Fail: {_fail}, Всего: {_total}";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00ff88"));

            if (_ok > 0)
                BtnCreateSub.Visibility = Visibility.Visible;
        });
    }

    private void TryInvoke(Action action)
    {
        try { Dispatcher.Invoke(action); } catch { }
    }

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        BtnStop.IsEnabled = false;
        StatusText.Text = "Остановлено";
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ff4466"));
    }

    private async void BtnCreateSub_Click(object sender, RoutedEventArgs e)
    {
        var okServers = Results.Where(r => r.ProxyOk && (!r.PingChecked || r.PingOk)).ToList();
        if (okServers.Count == 0) return;

        // Sort by grade (A+ > A > B+...) then by speed
        var sorted = okServers
            .OrderByDescending(r => r.DeepResult?.Grade ?? "F")
            .ThenByDescending(r => r.DeepResult?.SpeedMbps ?? 0)
            .ThenBy(r => r.DeepResult?.PacketLossPct ?? 100)
            .ToList();

        var uris = sorted.Select(r => r.Server.RawUri).Where(u => !string.IsNullOrEmpty(u)).ToList();
        if (uris.Count == 0) return;

        var plain = string.Join("\n", uris);
        var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plain));

        BtnCreateSub.IsEnabled = false;
        BtnCreateSub.Content = "⏳ Публикация...";

        try
        {
            var settings = SettingsService.Load();
            if (string.IsNullOrEmpty(settings.GitHubToken))
            {
                BtnCreateSub.Content = "✗ Нет токена GitHub";
                BtnCreateSub.IsEnabled = true;
                return;
            }
            var url = await GitHubService.CreateOrUpdateSubscription(base64, settings.GitHubToken);

            var aCount = sorted.Count(r => r.DeepResult?.Grade is "A+" or "A");
            LinkBorder.Visibility = Visibility.Visible;
            LinkText.Text = $"{url}\n\nОтфильтровано: {uris.Count} серверов (A+: {aCount})\nОтсортировано по скорости и стабильности";
            Clipboard.SetText(url);
            BtnCreateSub.Content = "✓ Опубликовано";
        }
        catch (Exception ex)
        {
            BtnCreateSub.Content = $"✗ Ошибка: {ex.Message}";
            BtnCreateSub.IsEnabled = true;
        }
    }

    private void BtnDone_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        Close();
    }

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _cts?.Cancel();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) => DragMove();
}

public class ServerRow : INotifyPropertyChanged
{
    private string _statusIcon = "○";
    private string _pingText = "...";
    private string _portText = "...";
    private string _tlsText = "...";
    private string _proxyText = "...";
    private string _proxyIp = "";
    private string _error = "";
    private string _speedText = "";
    private string _lossText = "";
    private string _gradeText = "";

    public string StatusIcon { get => _statusIcon; set { _statusIcon = value; OnPropertyChanged(); } }
    public string Name { get; set; } = "";
    public string PingText { get => _pingText; set { _pingText = value; OnPropertyChanged(); } }
    public string PortText { get => _portText; set { _portText = value; OnPropertyChanged(); } }
    public string TlsText { get => _tlsText; set { _tlsText = value; OnPropertyChanged(); } }
    public string ProxyText { get => _proxyText; set { _proxyText = value; OnPropertyChanged(); } }
    public string ProxyIp { get => _proxyIp; set { _proxyIp = value; OnPropertyChanged(); } }
    public string Error { get => _error; set { _error = value; OnPropertyChanged(); } }
    public string SpeedText { get => _speedText; set { _speedText = value; OnPropertyChanged(); } }
    public string LossText { get => _lossText; set { _lossText = value; OnPropertyChanged(); } }
    public string GradeText { get => _gradeText; set { _gradeText = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
