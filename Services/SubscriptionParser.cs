using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class SubscriptionParser
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(60) };

    public static async Task<SubscriptionData> FetchAndParse(string url)
    {
        var sub = new SubscriptionData { Url = url };
        try
        {
            var raw = await Http.GetStringAsync(url);
            var decoded = TryBase64Decode(raw);
            var lines = decoded.Split(new[] { '\r', '\n', '|' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;
                var server = ParseUri(trimmed);
                if (server != null)
                    sub.Servers.Add(server);
            }
        }
        catch (Exception ex)
        {
            sub.Error = ex.Message;
        }
        return sub;
    }

    public static List<ServerInfo> ParseFromText(string text)
    {
        var servers = new List<ServerInfo>();
        var lines = text.Split(new[] { '\r', '\n', '|' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            var server = ParseUri(trimmed);
            if (server != null)
                servers.Add(server);
        }
        return servers;
    }

    private static string TryBase64Decode(string input)
    {
        var trimmed = input.Trim();
        try
        {
            var bytes = Convert.FromBase64String(trimmed);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return trimmed;
        }
    }

    public static ServerInfo? ParseUri(string uri)
    {
        var scheme = uri.Split("://", 2, StringSplitOptions.None);
        if (scheme.Length < 2) return null;

        var protocol = scheme[0].ToLowerInvariant();
        var info = new ServerInfo { RawUri = uri };

        return protocol switch
        {
            "vless" => ParseVless(scheme[1], info),
            "trojan" => ParseTrojan(scheme[1], info),
            "hysteria2" or "hy2" => ParseHysteria2(scheme[1], info),
            "vmess" => ParseVmess(scheme[1], info),
            "ss" => ParseShadowsocks(scheme[1], info),
            "http" => ParseHttp(scheme[1], info),
            "socks" or "socks5" => ParseSocks(scheme[1], info),
            _ => null
        };
    }

    private static ServerInfo ParseVless(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.VlessReality;
        var parts = data.Split('@', 2);
        if (parts.Length < 2) return info;
        info.Uuid = parts[0];
        var hostPort = parts[1].Split('?', 2);
        var hp = hostPort[0].Split(':');
        if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 443; }

        var qs = ParseQuery(hostPort.Length > 1 ? hostPort[1] : "");
        info.Sni = qs.GetValueOrDefault("sni", "");
        info.Flow = qs.GetValueOrDefault("flow", "");
        info.Fingerprint = qs.GetValueOrDefault("fp", "chrome");
        info.PublicKey = qs.GetValueOrDefault("pbk", "");
        info.ShortId = qs.GetValueOrDefault("sid", "");

        if (qs.ContainsKey("security") && qs["security"] == "reality")
            info.Protocol = ProxyProtocol.VlessReality;
        else if (qs.ContainsKey("type") && qs["type"] == "ws")
            info.Protocol = ProxyProtocol.VlessWs;

        var fragment = data.Split('#');
        info.Name = fragment.Length > 1 ? Uri.UnescapeDataString(fragment[^1]) : info.Host;
        return info;
    }

    private static ServerInfo ParseTrojan(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.Trojan;
        var parts = data.Split('@', 2);
        if (parts.Length < 2) return info;
        info.Password = parts[0];
        var hostPort = parts[1].Split('?', 2);
        var hp = hostPort[0].Split(':');
        if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 443; }

        var qs = ParseQuery(hostPort.Length > 1 ? hostPort[1] : "");
        info.Sni = qs.GetValueOrDefault("sni", "");
        info.Fingerprint = qs.GetValueOrDefault("fp", "chrome");

        var fragment = data.Split('#');
        info.Name = fragment.Length > 1 ? Uri.UnescapeDataString(fragment[^1]) : info.Host;
        return info;
    }

    private static ServerInfo ParseHysteria2(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.Hysteria2;
        var parts = data.Split('@', 2);
        if (parts.Length < 2) return info;
        info.Password = parts[0];
        var hostPort = parts[1].Split('?', 2);
        var hp = hostPort[0].Split(':');
        if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 8443; }

        var qs = ParseQuery(hostPort.Length > 1 ? hostPort[1] : "");
        info.Sni = qs.GetValueOrDefault("sni", "");

        var fragment = data.Split('#');
        info.Name = fragment.Length > 1 ? Uri.UnescapeDataString(fragment[^1]) : info.Host;
        return info;
    }

    private static ServerInfo ParseVmess(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.VmessWs;
        try
        {
            var json = TryBase64Decode(data);
            var psMatch = Regex.Match(json, @"""ps""\s*:\s*""([^""]*)""");
            var addMatch = Regex.Match(json, @"""add""\s*:\s*""([^""]*)""");
            var portMatch = Regex.Match(json, @"""port""\s*:\s*""?(\d+)""?");
            var idMatch = Regex.Match(json, @"""id""\s*:\s*""([^""]*)""");
            var netMatch = Regex.Match(json, @"""net""\s*:\s*""([^""]*)""");
            var sniMatch = Regex.Match(json, @"""sni""\s*:\s*""([^""]*)""");
            var pathMatch = Regex.Match(json, @"""path""\s*:\s*""([^""]*)""");

            if (addMatch.Success) info.Host = addMatch.Groups[1].Value;
            if (portMatch.Success) info.Port = int.Parse(portMatch.Groups[1].Value);
            if (idMatch.Success) info.Uuid = idMatch.Groups[1].Value;
            if (sniMatch.Success) info.Sni = sniMatch.Groups[1].Value;
            if (pathMatch.Success) info.Path = pathMatch.Groups[1].Value;
            info.Name = psMatch.Success ? psMatch.Groups[1].Value : info.Host;
            info.Flow = netMatch.Success && netMatch.Groups[1].Value == "ws" ? "ws" : "";
        }
        catch { info.Name = info.Host; }
        return info;
    }

    private static ServerInfo ParseShadowsocks(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.Shadowsocks;
        var clean = data;
        var fragment = data.Split('#');
        if (fragment.Length > 1)
        {
            info.Name = Uri.UnescapeDataString(fragment[^1]);
            clean = fragment[0];
        }

        if (clean.Contains('@'))
        {
            var parts = clean.Split('@', 2);
            info.Password = parts[0];
            var hp = parts[1].Split(':');
            if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 8388; }
        }
        else
        {
            var decoded = TryBase64Decode(clean);
            var parts = decoded.Split('@', 2);
            if (parts.Length >= 2)
            {
                var methodPass = parts[0].Split(':', 2);
                if (methodPass.Length >= 2) info.Password = methodPass[1];
                var hp = parts[1].Split(':');
                if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 8388; }
            }
        }
        if (string.IsNullOrEmpty(info.Name)) info.Name = info.Host;
        return info;
    }

    private static ServerInfo ParseHttp(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.HttpProxy;
        var parts = data.Split('@', 2);
        if (parts.Length >= 2)
        {
            var userPass = parts[0].Split(':', 2);
            if (userPass.Length >= 2) { info.Password = userPass[1]; }
            var hp = parts[1].Split(':');
            if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 80; }
        }
        var fragment = data.Split('#');
        info.Name = fragment.Length > 1 ? Uri.UnescapeDataString(fragment[^1]) : info.Host;
        return info;
    }

    private static ServerInfo ParseSocks(string data, ServerInfo info)
    {
        info.Protocol = ProxyProtocol.Socks5;
        var parts = data.Split('@', 2);
        if (parts.Length >= 2)
        {
            var hp = parts[1].Split(':');
            if (hp.Length >= 2) { info.Host = hp[0]; info.Port = int.TryParse(hp[1], out var p) ? p : 1080; }
        }
        var fragment = data.Split('#');
        info.Name = fragment.Length > 1 ? Uri.UnescapeDataString(fragment[^1]) : info.Host;
        return info;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return dict;
        foreach (var pair in query.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2)
                dict[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
        }
        return dict;
    }
}
