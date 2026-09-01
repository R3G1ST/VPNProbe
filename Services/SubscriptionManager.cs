using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class SubscriptionManager
{
    private static readonly string AppDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VPNProbe");
    private static readonly string FilePath = Path.Combine(AppDir, "subscriptions.json");

    public static List<SavedSubscription> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new();
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<List<SavedSubscription>>(json) ?? new();
        }
        catch { return new(); }
    }

    public static void Save(List<SavedSubscription> items)
    {
        try
        {
            Directory.CreateDirectory(AppDir);
            var json = JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(FilePath, json);
        }
        catch { }
    }

    public static void Add(string url, int serverCount = 0, string? customName = null)
    {
        var items = Load();
        if (items.Any(x => x.Url == url)) return;
        items.Add(new SavedSubscription
        {
            Name = string.IsNullOrWhiteSpace(customName) ? DeriveName(url) : customName,
            Url = url,
            SavedAt = DateTime.Now,
            ServerCount = serverCount
        });
        Save(items);
    }

    public static void Remove(string url)
    {
        var items = Load();
        items.RemoveAll(x => x.Url == url);
        Save(items);
    }

    public static string DeriveName(string url)
    {
        try
        {
            var uri = new Uri(url);
            var host = uri.Host;
            if (host.StartsWith("www.")) host = host[4..];
            var parts = host.Split('.');
            if (parts.Length >= 2)
                return string.Join(" ", parts.Take(parts.Length - 1));
            return host;
        }
        catch
        {
            return url.Length > 30 ? url[..30] + "..." : url;
        }
    }
}
