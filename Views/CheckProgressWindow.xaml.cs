using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
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

    public List<CheckResultDisplay> Results { get; } = new();

    public CheckProgressWindow()
    {
        InitializeComponent();
        ServerGrid.ItemsSource = _rows;
    }

    public async Task RunCheckAsync(string url, bool checkPing, bool checkPortTls, bool checkProxy, bool checkDpi)
    {
        _cts = new CancellationTokenSource();
        
        _done = _ok = _fail = 0;

        List<ServerInfo> servers;
        try
        {
            StatusText.Text = "Загрузка подписки...";
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
                if (checkPing)
                {
                    var ping = await PingChecker.CheckAsync(server, ct);
                    display.PingMs = ping.PingMs;
                    display.PingOk = ping.PingOk;
                    display.PingChecked = true;
                    await Dispatcher.InvokeAsync(() => row.PingText = ping.PingOk ? $"{ping.PingMs}ms" : "—");
                }

                if (checkPortTls)
                {
                    var portTls = await PortTlsChecker.CheckAsync(server, ct);
                    display.PortOpen = portTls.PortOpen;
                    display.TlsOk = portTls.TlsOk;
                    display.TlsExpiry = portTls.TlsExpiry;
                    if (portTls.Error != "") display.Error = portTls.Error;
                    await Dispatcher.InvokeAsync(() =>
                    {
                        row.PortText = portTls.PortOpen ? "✓" : "✗";
                        row.TlsText = portTls.TlsOk ? "✓" : "✗";
                    });
                }

                if (checkProxy && display.PortOpen)
                {
                    var proxy = await ProxyChecker.CheckAsync(server, ct);
                    display.ProxyOk = proxy.ProxyOk;
                    display.ProxyIp = proxy.ProxyIp;
                    if (proxy.Error != "") display.Error = proxy.Error;
                    await Dispatcher.InvokeAsync(() =>
                    {
                        row.ProxyText = proxy.ProxyOk ? "✓" : "✗";
                        row.ProxyIp = proxy.ProxyIp;
                        if (!string.IsNullOrEmpty(proxy.Error)) row.Error = proxy.Error;
                    });
                }

                var isOk = display.ProxyOk && (!display.PingChecked || display.PingOk);
                if (isOk) Interlocked.Increment(ref _ok); else Interlocked.Increment(ref _fail);
            }
            catch { Interlocked.Increment(ref _fail); }

            var progress = Interlocked.Increment(ref _done);
            Results.Add(display);

            await Dispatcher.InvokeAsync(() =>
            {
                var isOkRow = display.ProxyOk && (!display.PingChecked || display.PingOk);
                row.StatusIcon = isOkRow ? "✓" : "✗";
                if (!string.IsNullOrEmpty(display.Error) && string.IsNullOrEmpty(row.Error))
                    row.Error = display.Error;

                OkCount.Text = $"OK: {_ok}";
                FailCount.Text = $"Fail: {_fail}";
                TotalCount.Text = $"{_done}/{_total}";
                ProgressBar.Value = (double)_done / _total * 100;
                StatusText.Text = $"{_done}/{_total} — {server.Name}";
            });
        });

        Dispatcher.Invoke(() =>
        {
            BtnStop.Visibility = Visibility.Collapsed;
            BtnDone.Visibility = Visibility.Visible;
            TitleText.Text = "Проверка завершена";
            StatusText.Text = $"Завершено — OK: {_ok}, Fail: {_fail}, Всего: {_total}";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00ff88"));

            SummaryBorder.Visibility = Visibility.Visible;
            SummaryText.Text = $"OK: {_ok}  |  Fail: {_fail}  |  Всего: {_total}";
        });
    }

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        BtnStop.IsEnabled = false;
        StatusText.Text = "Остановлено";
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ff4466"));
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

    public string StatusIcon { get => _statusIcon; set { _statusIcon = value; OnPropertyChanged(); } }
    public string Name { get; set; } = "";
    public string PingText { get => _pingText; set { _pingText = value; OnPropertyChanged(); } }
    public string PortText { get => _portText; set { _portText = value; OnPropertyChanged(); } }
    public string TlsText { get => _tlsText; set { _tlsText = value; OnPropertyChanged(); } }
    public string ProxyText { get => _proxyText; set { _proxyText = value; OnPropertyChanged(); } }
    public string ProxyIp { get => _proxyIp; set { _proxyIp = value; OnPropertyChanged(); } }
    public string Error { get => _error; set { _error = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
