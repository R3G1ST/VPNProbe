using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace VPNProbe.Services;

public static class GitHubService
{
    private const string Repo = "R3G1ST/VPNProbe";
    private const string Branch = "main";
    private const string SubscriptionsPath = "subscriptions/filtered.txt";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    private static string RawUrl => $"https://raw.githubusercontent.com/{Repo}/{Branch}/{SubscriptionsPath}";

    public static async Task<string> CreateOrUpdateSubscription(string base64Content, string token)
    {
        var existingSha = await GetFileSha(token);

        var body = new
        {
            message = "update: filtered subscription",
            content = base64Content,
            branch = Branch,
            sha = (string?)existingSha
        };

        var json = JsonSerializer.Serialize(body);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var req = new HttpRequestMessage(HttpMethod.Put,
            $"https://api.github.com/repos/{Repo}/contents/{SubscriptionsPath}");
        req.Headers.Authorization = new("Bearer", token);
        req.Headers.UserAgent.ParseAdd("VPNProbe/1.0");
        req.Content = content;

        var resp = await Http.SendAsync(req);
        resp.EnsureSuccessStatusCode();

        return RawUrl;
    }

    private static async Task<string?> GetFileSha(string token)
    {
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.github.com/repos/{Repo}/contents/{SubscriptionsPath}?ref={Branch}");
            req.Headers.Authorization = new("Bearer", token);
            req.Headers.UserAgent.ParseAdd("VPNProbe/1.0");

            var resp = await Http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("sha").GetString();
        }
        catch { return null; }
    }

    public static string GetRawUrl(string path)
    {
        return $"https://raw.githubusercontent.com/{Repo}/{Branch}/{path}";
    }

    public static async Task<string> CreateOrUpdateProtocolSubscription(string protocol, string base64Content, string token)
    {
        var path = $"subscriptions/online/{protocol}.txt";
        var existingSha = await GetFileShaByPath(token, path);

        var body = new
        {
            message = $"update: {protocol} subscription",
            content = base64Content,
            branch = Branch,
            sha = (string?)existingSha
        };

        var json = JsonSerializer.Serialize(body);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var req = new HttpRequestMessage(HttpMethod.Put,
            $"https://api.github.com/repos/{Repo}/contents/{path}");
        req.Headers.Authorization = new("Bearer", token);
        req.Headers.UserAgent.ParseAdd("VPNProbe/1.0");
        req.Content = content;

        var resp = await Http.SendAsync(req);
        resp.EnsureSuccessStatusCode();

        return GetRawUrl(path);
    }

    private static async Task<string?> GetFileShaByPath(string token, string path)
    {
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.github.com/repos/{Repo}/contents/{path}?ref={Branch}");
            req.Headers.Authorization = new("Bearer", token);
            req.Headers.UserAgent.ParseAdd("VPNProbe/1.0");

            var resp = await Http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("sha").GetString();
        }
        catch { return null; }
    }
}
