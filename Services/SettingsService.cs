using System;
using System.IO;
using System.Text.Json;

namespace VPNProbe.Services;

public static class SettingsService
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "VPNProbe", "settings.json");

    private static AppSettings? _cache;

    public static AppSettings Load()
    {
        if (_cache != null) return _cache;
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                _cache = JsonSerializer.Deserialize<AppSettings>(json) ?? new();
                return _cache;
            }
        }
        catch { }
        _cache = new AppSettings();
        return _cache;
    }

    public static void Save(AppSettings settings)
    {
        _cache = settings;
        try
        {
            var dir = Path.GetDirectoryName(SettingsPath);
            if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);
        }
        catch { }
    }
}

public class AppSettings
{
    public string GitHubToken { get; set; } = "";
    public string DefaultSubscriptionUrl { get; set; } = "";
}
