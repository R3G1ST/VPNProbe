using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using VPNProbe.Models;
using VPNProbe.Services;

namespace VPNProbe;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CheckResultDisplay> _results = new();

    public MainWindow()
    {
        InitializeComponent();
        ResultsGrid.ItemsSource = _results;
        try
        {
            var icoPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
            if (System.IO.File.Exists(icoPath))
                this.Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(icoPath, UriKind.Absolute));
            else
            {
                var uri = new Uri("pack://application:,,,/app.png", UriKind.Absolute);
                this.Icon = new System.Windows.Media.Imaging.BitmapImage(uri);
            }
        }
        catch { }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            ToggleMaximize();
        else
            DragMove();
    }

    private void BtnMinimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void BtnMaximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void BtnChooseLink_Click(object sender, RoutedEventArgs e)
    {
        var win = new Views.SavedLinksWindow { Owner = this };
        if (win.ShowDialog() == true && win.SelectedLink != null)
        {
            InputUrl.Text = win.SelectedLink.Url;
        }
    }

    private void BtnSaveLink_Click(object sender, RoutedEventArgs e)
    {
        var url = InputUrl.Text.Trim();
        if (string.IsNullOrEmpty(url) || !url.StartsWith("http")) return;

        var name = Services.SubscriptionManager.DeriveName(url);
        var inputBox = new Window
        {
            Title = "Сохранить ссылку",
            Width = 400, Height = 180,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            WindowStyle = WindowStyle.None,
            AllowsTransparency = true,
            Background = System.Windows.Media.Brushes.Transparent,
            ResizeMode = ResizeMode.NoResize
        };

        var border = new System.Windows.Controls.Border
        {
            Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#08080e")),
            BorderBrush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#181820")),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16)
        };

        var stack = new System.Windows.Controls.StackPanel();
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "Название ссылки:",
            Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#888899")),
            FontSize = 11, Margin = new Thickness(0, 0, 0, 6)
        });

        var nameBox = new System.Windows.Controls.TextBox
        {
            Text = name,
            FontFamily = new System.Windows.Media.FontFamily("Cascadia Code, Consolas"),
            FontSize = 13,
            Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#0a0a12")),
            Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#e0e0e0")),
            BorderBrush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#181820")),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 10)
        };
        stack.Children.Add(nameBox);

        var btnPanel = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        var okBtn = new System.Windows.Controls.Button
        {
            Content = "Сохранить", FontSize = 11, Cursor = Cursors.Hand,
            Foreground = System.Windows.Media.Brushes.Black,
            Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00ff88")),
            FontFamily = new System.Windows.Media.FontFamily("Cascadia Code, Consolas"),
            FontWeight = FontWeights.Bold, Padding = new Thickness(16, 4, 16, 4), BorderThickness = new Thickness(0)
        };
        var cancelBtn = new System.Windows.Controls.Button
        {
            Content = "Отмена", FontSize = 11, Cursor = Cursors.Hand,
            Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#888899")),
            Background = System.Windows.Media.Brushes.Transparent,
            FontFamily = new System.Windows.Media.FontFamily("Cascadia Code, Consolas"),
            Padding = new Thickness(16, 4, 16, 4), BorderThickness = new Thickness(0),
            Margin = new Thickness(8, 0, 0, 0)
        };
        okBtn.Click += (_, _) => { inputBox.DialogResult = true; inputBox.Close(); };
        cancelBtn.Click += (_, _) => { inputBox.DialogResult = false; inputBox.Close(); };
        btnPanel.Children.Add(okBtn);
        btnPanel.Children.Add(cancelBtn);
        stack.Children.Add(btnPanel);

        border.Child = stack;
        inputBox.Content = border;
        nameBox.SelectAll();
        nameBox.Focus();

        if (inputBox.ShowDialog() == true)
        {
            var chosenName = nameBox.Text.Trim();
            if (string.IsNullOrEmpty(chosenName)) chosenName = name;
            var items = Services.SubscriptionManager.Load();
            if (!items.Any(x => x.Url == url))
            {
                items.Add(new Models.SavedSubscription { Name = chosenName, Url = url, SavedAt = DateTime.Now, ServerCount = _results.Count });
                Services.SubscriptionManager.Save(items);
            }
            AnimateStatus($"Сохранено: {chosenName}", "#ffcc00");
        }
    }

    private async void BtnStart_Click(object sender, RoutedEventArgs e)
    {
        var input = InputUrl.Text.Trim();
        if (string.IsNullOrEmpty(input)) return;

        var win = new Views.CheckProgressWindow { Owner = this };
        var checkTask = win.RunCheckAsync(input,
            ChkPing.IsChecked == true,
            ChkPortTls.IsChecked == true,
            ChkProxy.IsChecked == true,
            ChkDpi.IsChecked == true);

        win.ShowDialog();
        await checkTask;

        if (win.DialogResult == true)
        {
            _results.Clear();
            foreach (var r in win.Results.OrderBy(r => r.PingMs >= 0 ? r.PingMs : int.MaxValue))
                _results.Add(r);

            foreach (var col in ResultsGrid.Columns)
            {
                if (col.Width.IsStar || col.Width.IsAuto) continue;
                col.Width = new DataGridLength(1, DataGridLengthUnitType.Auto);
            }

            var ok = win.Results.Count(r => r.ProxyOk && (!r.PingChecked || r.PingOk));
            AnimateStatus($"Завершено — OK: {ok}, Fail: {win.Results.Count - ok}, Всего: {win.Results.Count}", "#00ff88");
        }
    }

    private void AnimateStatus(string text, string colorHex)
    {
        StatusText.Text = text;
        var color = (Color)ColorConverter.ConvertFromString(colorHex);
        StatusText.Foreground = new SolidColorBrush(color);

        var anim = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
        StatusText.BeginAnimation(OpacityProperty, anim);

        StatusDot.Background = new SolidColorBrush(color);
    }

    private void ResultsGrid_MouseRightButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (ResultsGrid.SelectedItem is CheckResultDisplay)
            ResultsGrid.ContextMenu.IsOpen = true;
    }

    private void MenuCopyUri_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is CheckResultDisplay item)
        {
            Clipboard.SetText(item.Server.RawUri);
            StatusText.Text = "Скопировано в буфер обмена";
        }
    }

    private void MenuCopyPodkop_Click(object sender, RoutedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is CheckResultDisplay item)
        {
            var link = GeneratePodkopLink(item.Server);
            Clipboard.SetText(link);
            StatusText.Text = "Скопировано для Podkop";
        }
    }

    private static string GeneratePodkopLink(ServerInfo s)
    {
        var uri = s.RawUri.Trim();

        if (uri.Contains("#"))
        {
            var hashIndex = uri.LastIndexOf("#");
            var beforeHash = uri.Substring(0, hashIndex);
            var afterHash = uri.Substring(hashIndex + 1);
            var cleanName = MakeAscii(afterHash);
            uri = beforeHash + "#" + cleanName;
        }

        uri = uri.Replace(" ", "%20");
        return uri;
    }

    private static string MakeAscii(string input)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var c in input)
        {
            if (c >= 'a' && c <= 'z') sb.Append(c);
            else if (c >= 'A' && c <= 'Z') sb.Append(c);
            else if (c >= '0' && c <= '9') sb.Append(c);
            else if (c == '-' || c == '_') sb.Append(c);
            else if (c == ' ') sb.Append('_');
        }
        return sb.Length > 0 ? sb.ToString() : "Server";
    }

    private void TabServers_Click(object sender, MouseButtonEventArgs e)
    {
        ServersPanel.Visibility = Visibility.Visible;
        AuditPanel.Visibility = Visibility.Collapsed;
        TabServersText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00ff88"));
        TabServersText.FontWeight = FontWeights.Bold;
        TabServersBg.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#08080e"));
        TabAuditText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888899"));
        TabAuditText.FontWeight = FontWeights.Normal;
        TabAuditBg.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0a0a12"));
    }

    private void TabAudit_Click(object sender, MouseButtonEventArgs e)
    {
        ServersPanel.Visibility = Visibility.Collapsed;
        AuditPanel.Visibility = Visibility.Visible;
        TabAuditText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00ff88"));
        TabAuditText.FontWeight = FontWeights.Bold;
        TabAuditBg.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#08080e"));
        TabServersText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888899"));
        TabServersText.FontWeight = FontWeights.Normal;
        TabServersBg.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0a0a12"));
    }

    private CancellationTokenSource? _auditCts;
    private Action<AuditResult>? _onAuditComplete;
    private List<AuditResult>? _lastAuditResults;

    private void BtnStartAudit_Click(object sender, RoutedEventArgs e)
    {
        StartAudit();
    }

    private void BtnCopyLog_Click(object sender, RoutedEventArgs e)
    {
        if (_lastAuditResults == null) return;
        var log = GenerateAuditLog(_lastAuditResults);
        Clipboard.SetText(log);
        StatusText.Text = "Лог скопирован";
    }

    private string GenerateAuditLog(List<AuditResult> results)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== VPNProbe Audit Log ===");
        sb.AppendLine($"Дата: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        double overallScore = results.Count > 0 ? results.Average(r => r.Score) : 0;
        string overallGrade = overallScore >= 90 ? "A+" : overallScore >= 80 ? "A" : overallScore >= 70 ? "B" : overallScore >= 60 ? "C" : "F";
        sb.AppendLine($"ОБЩАЯ ОЦЕНКА: {overallGrade} ({overallScore:F0}/100)");
        sb.AppendLine(new string('=', 40));

        foreach (var r in results)
        {
            sb.AppendLine();
            sb.AppendLine($"[{r.Grade}] {r.Name} ({r.Category}) — {r.Score:F0}/100");
            foreach (var c in r.Checks)
            {
                var icon = c.Passed ? "+" : c.Severity == "critical" ? "!!" : "!";
                sb.AppendLine($"  {icon} {c.Name}: {c.Value}");
            }
            if (!string.IsNullOrEmpty(r.Details))
                sb.AppendLine($"  Детали: {r.Details}");
        }

        return sb.ToString();
    }

    private async void StartAudit()
    {
        _auditCts = new CancellationTokenSource();
        AuditResults.Children.Clear();
        BtnStartAudit.IsEnabled = false;

        var header = new TextBlock
        {
            Text = "🔍 Аудит запущен",
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ffcc00")),
            FontSize = 14, FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 10, 0, 10)
        };
        AuditResults.Children.Add(header);

        var steps = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        var stepDict = new Dictionary<string, TextBlock>();
        string[] stepNames = { "IP Info", "DPI Детекция", "Скорость", "Bufferbloat", "DNS", "Гео-блокировка" };
        foreach (var name in stepNames)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            var icon = new TextBlock { Text = "○", Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#333340")), FontSize = 12, Width = 20 };
            var label = new TextBlock { Text = name, Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#666680")), FontSize = 12 };
            var detail = new TextBlock { Text = "", Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555566")), FontSize = 11, Margin = new Thickness(8, 0, 0, 0) };
            row.Children.Add(icon);
            row.Children.Add(label);
            row.Children.Add(detail);
            steps.Children.Add(row);
            stepDict[name] = icon;
        }
        AuditResults.Children.Add(steps);

        var progressBorder = new Border
        {
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#08080e")),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 0, 0, 8)
        };
        var progressText = new TextBlock
        {
            Text = "Подготовка...",
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888899")),
            FontSize = 12
        };
        progressBorder.Child = progressText;
        AuditResults.Children.Add(progressBorder);

        AuditOrchestrator.OnProgress += (name, msg) =>
        {
            Dispatcher.Invoke(() =>
            {
                progressText.Text = msg;
                if (stepDict.TryGetValue(name, out var icon))
                {
                    icon.Text = "◉";
                    icon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ffcc00"));
                }
            });
        };

        var results = new List<AuditResult>();
        _onAuditComplete = (result) =>
        {
            Dispatcher.Invoke(() =>
            {
                AuditResults.Children.Insert(AuditResults.Children.Count - 1, CreateAuditCard(result));
                if (stepDict.TryGetValue(result.Name, out var icon))
                {
                    var color = result.Grade.StartsWith("A") ? "#00ff88" : result.Grade == "B" ? "#ffcc00" : result.Grade == "C" ? "#ff8844" : "#ff4466";
                    icon.Text = "✓";
                    icon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
                }
            });
            results.Add(result);
        };
        AuditOrchestrator.OnCheckComplete += _onAuditComplete;

        try
        {
            var allResults = await AuditOrchestrator.RunFullAuditAsync(_auditCts.Token);
            AuditResults.Children.Remove(progressBorder);
            AuditResults.Children.Remove(header);

            var overallScore = allResults.Count > 0 ? allResults.Average(r => r.Score) : 0;
            var overallGrade = overallScore >= 90 ? "A+" : overallScore >= 80 ? "A" : overallScore >= 70 ? "B" : overallScore >= 60 ? "C" : "F";
            var gradeColor = overallGrade.StartsWith("A") ? "#00ff88" : overallGrade == "B" ? "#ffcc00" : overallGrade == "C" ? "#ff8844" : "#ff4466";

            var summary = new Border
            {
                Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#08080e")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(16),
                Margin = new Thickness(0, 0, 0, 12),
                BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(gradeColor)),
                BorderThickness = new Thickness(1)
            };
            var summaryPanel = new StackPanel();
            summaryPanel.Children.Add(new TextBlock
            {
                Text = $"Общая оценка: {overallGrade} ({overallScore:F0}/100)",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(gradeColor)),
                FontSize = 18, FontWeight = FontWeights.Bold
            });
            summary.Child = summaryPanel;
            AuditResults.Children.Insert(0, summary);

            _lastAuditResults = allResults;
            BtnCopyLog.IsEnabled = true;

            AnimateStatus($"Аудит завершён — {overallGrade}", "#00ff88");
        }
        catch (Exception ex)
        {
            AuditResults.Children.Remove(progressBorder);
            header.Text = $"Ошибка: {ex.Message}";
            header.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ff4466"));
        }
        finally
        {
            if (_onAuditComplete != null)
                AuditOrchestrator.OnCheckComplete -= _onAuditComplete;
            BtnStartAudit.IsEnabled = true;
        }
    }

    private Border CreateAuditCard(AuditResult result)
    {
        var gradeColor = result.Grade.StartsWith("A") ? "#00ff88" : result.Grade == "B" ? "#ffcc00" : result.Grade == "C" ? "#ff8844" : "#ff4466";

        var border = new Border
        {
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#08080e")),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12),
            Margin = new Thickness(0, 0, 0, 8),
            BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#181820")),
            BorderThickness = new Thickness(1)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Auto) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var gradeBlock = new TextBlock
        {
            Text = result.Grade,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(gradeColor)),
            FontSize = 28, FontWeight = FontWeights.Bold,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 16, 0),
            Width = 50
        };
        Grid.SetColumn(gradeBlock, 0);
        grid.Children.Add(gradeBlock);

        var details = new StackPanel();
        details.Children.Add(new TextBlock
        {
            Text = $"{result.Name}  •  {result.Category}",
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#e0e0e0")),
            FontSize = 13, FontWeight = FontWeights.Bold
        });

        foreach (var check in result.Checks)
        {
            var checkPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            var icon = check.Passed ? "✓" : check.Severity == "critical" ? "✗" : "⚠";
            var iconColor = check.Passed ? "#00ff88" : check.Severity == "critical" ? "#ff4466" : "#ffcc00";
            checkPanel.Children.Add(new TextBlock
            {
                Text = $"{icon} ",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(iconColor)),
                FontSize = 11, FontWeight = FontWeights.Bold
            });
            checkPanel.Children.Add(new TextBlock
            {
                Text = $"{check.Name}: {check.Value}",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888899")),
                FontSize = 11
            });
            details.Children.Add(checkPanel);
        }

        if (!string.IsNullOrEmpty(result.Details))
        {
            details.Children.Add(new TextBlock
            {
                Text = result.Details,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#666680")),
                FontSize = 10, Margin = new Thickness(0, 4, 0, 0)
            });
        }

        Grid.SetColumn(details, 1);
        grid.Children.Add(details);
        border.Child = grid;
        return border;
    }
}

public class CheckResultDisplay : System.ComponentModel.INotifyPropertyChanged
{
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public void NotifyStatusChanged()
    {
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Status)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(PingDisplay)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(PortDisplay)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(TlsDisplay)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(ProxyDisplay)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(ProxyIp)));
        PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(Error)));
    }

    public ServerInfo Server { get; set; } = new();
    public int PingMs { get; set; } = -1;
    public bool PingOk { get; set; }
    public bool PingChecked { get; set; }
    public bool PortOpen { get; set; }
    public bool TlsOk { get; set; }
    public string TlsExpiry { get; set; } = "";
    public bool ProxyOk { get; set; }
    public string ProxyIp { get; set; } = "";
    public bool DpiBlocked { get; set; }
    public string Error { get; set; } = "";
    public Services.DeepCheckResult? DeepResult { get; set; }

    public string PingDisplay => PingMs >= 0 ? $"{PingMs}ms" : "0ms";
    public string PortDisplay => PortOpen ? "✓" : "✗";
    public string TlsDisplay => TlsOk ? "✓" : "✗";
    public string ProxyDisplay => ProxyOk ? "✓" : "—";

    public string Status
    {
        get
        {
            if (DpiBlocked) return "DPI blocked";
            if (PingChecked && !PingOk) return "No ping";
            if (ProxyOk) return "OK";
            if (!PortOpen) return "Port blocked";
            if (!TlsOk) return "TLS fail";
            return "Fail";
        }
    }
}
