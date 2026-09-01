using System;
using System.Linq;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using VPNProbe.Models;
using VPNProbe.Services;

namespace VPNProbe.Views;

public partial class SavedLinksWindow : Window
{
    private SavedSubscription? _selected;
    public SavedSubscription? SelectedLink => _selected;

    public SavedLinksWindow()
    {
        InitializeComponent();
        LoadList();
    }

    private void LoadList()
    {
        LinksList.Children.Clear();
        var items = SubscriptionManager.Load();

        if (items.Count == 0)
        {
            LinksList.Children.Add(new System.Windows.Controls.TextBlock
            {
                Text = "Нет сохранённых ссылок",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555566")),
                FontSize = 12,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 20, 0, 20)
            });
            StatusText.Text = "Пусто";
            return;
        }

        foreach (var item in items)
            LinksList.Children.Add(CreateRow(item));

        StatusText.Text = $"Сохранено: {items.Count}";
    }

    private System.Windows.Controls.Border CreateRow(SavedSubscription item)
    {
        var border = new System.Windows.Controls.Border
        {
            Background = Brushes.Transparent,
            BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#181820")),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(12, 8, 12, 8),
            Cursor = Cursors.Hand,
            Tag = item
        };
        border.MouseLeftButtonDown += Row_Click;
        border.MouseEnter += (_, _) => border.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#12121e"));
        border.MouseLeave += (_, _) => { if (border.BorderBrush != AccentBrush) border.Background = Brushes.Transparent; };

        var grid = new System.Windows.Controls.Grid();
        grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = GridLength.Auto });

        var stack = new System.Windows.Controls.StackPanel();
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = item.Name,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#e0e0e0")),
            FontSize = 12, FontWeight = FontWeights.Bold
        });
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = item.Url.Length > 45 ? item.Url[..45] + "..." : item.Url,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555566")),
            FontSize = 10, Margin = new Thickness(0, 2, 0, 0)
        });
        System.Windows.Controls.Grid.SetColumn(stack, 0);
        grid.Children.Add(stack);

        if (item.ServerCount > 0)
        {
            var cnt = new System.Windows.Controls.TextBlock
            {
                Text = $"{item.ServerCount} серверов",
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#00ff88")),
                FontSize = 10, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0)
            };
            System.Windows.Controls.Grid.SetColumn(cnt, 1);
            grid.Children.Add(cnt);
        }

        var del = new System.Windows.Controls.Button
        {
            Content = "✕", FontSize = 11, Cursor = Cursors.Hand, Tag = item,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#ff4466")),
            Background = Brushes.Transparent, BorderThickness = new Thickness(0),
            Padding = new Thickness(6, 2, 6, 2)
        };
        del.Click += BtnDelete_Click;
        System.Windows.Controls.Grid.SetColumn(del, 2);
        grid.Children.Add(del);

        border.Child = grid;
        return border;
    }

    private static readonly SolidColorBrush AccentBrush = new((Color)ColorConverter.ConvertFromString("#00ff88"));

    private void Row_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is System.Windows.Controls.Border border && border.Tag is SavedSubscription item)
        {
            _selected = item;
            BtnSelect.IsEnabled = true;
            foreach (var child in LinksList.Children)
                if (child is System.Windows.Controls.Border b)
                    b.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#181820"));
            border.BorderBrush = AccentBrush;
        }
    }

    private void BtnSelect_Click(object sender, RoutedEventArgs e)
    {
        if (_selected != null) { DialogResult = true; Close(); }
    }

    private void BtnAdd_Click(object sender, RoutedEventArgs e)
    {
        LinksList.Visibility = Visibility.Collapsed;
        AddPanel.Visibility = Visibility.Visible;
        AddUrlInput.Text = "https://";
        AddNameInput.Text = "";
        AddUrlInput.Focus();
    }

    private void BtnAddConfirm_Click(object sender, RoutedEventArgs e)
    {
        var url = AddUrlInput.Text.Trim();
        if (string.IsNullOrEmpty(url) || !url.StartsWith("http")) return;
        var name = AddNameInput.Text.Trim();
        if (string.IsNullOrEmpty(name))
            name = SubscriptionManager.DeriveName(url);

        var items = SubscriptionManager.Load();
        if (!items.Any(x => x.Url == url))
        {
            items.Add(new SavedSubscription { Name = name, Url = url, SavedAt = DateTime.Now });
            SubscriptionManager.Save(items);
        }

        AddPanel.Visibility = Visibility.Collapsed;
        LinksList.Visibility = Visibility.Visible;
        LoadList();
    }

    private void BtnAddCancel_Click(object sender, RoutedEventArgs e)
    {
        AddPanel.Visibility = Visibility.Collapsed;
        LinksList.Visibility = Visibility.Visible;
    }

    private void BtnDelete_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is SavedSubscription item)
        {
            SubscriptionManager.Remove(item.Url);
            LoadList();
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) => DragMove();
    private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();
}
