using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class ProxyChecker
{
    private static readonly string SingBoxPath = FindSingBox();

    private static string FindSingBox()
    {
        var candidates = new[]
        {
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sing-box.exe"),
            @"C:\sing-box\sing-box.exe",
            @"C:\Tools\sing-box.exe",
        };
        foreach (var c in candidates)
            if (File.Exists(c)) return c;
        return "";
    }

    public static async Task<CheckResult> CheckAsync(ServerInfo server, CancellationToken ct = default)
    {
        var result = new CheckResult { Server = server };

        if (string.IsNullOrEmpty(SingBoxPath))
        {
            result.Error = "sing-box.exe not found";
            return result;
        }

        var configPath = Path.Combine(Path.GetTempPath(), $"vpnprobe_{Guid.NewGuid():N}.json");
        try
        {
            var config = GenerateConfig(server);
            await File.WriteAllTextAsync(configPath, config, ct);

            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = SingBoxPath,
                Arguments = $"run -c \"{configPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            process.Start();

            await Task.Delay(2000, ct);

            var testUrl = "http://cp.cloudflare.com/";
            var success = await TestThroughProxy(testUrl, ct);

            try { process.Kill(); } catch { }

            if (success)
            {
                result.ProxyOk = true;
                var ip = await GetExternalIpAsync(ct);
                result.ProxyIp = ip;
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            try { File.Delete(configPath); } catch { }
        }
        return result;
    }

    private static async Task<bool> TestThroughProxy(string url, CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient();
            http.Timeout = TimeSpan.FromSeconds(8);
            var resp = await http.GetAsync(url, ct);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private static async Task<string> GetExternalIpAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient();
            http.Timeout = TimeSpan.FromSeconds(5);
            return (await http.GetStringAsync("https://api.ipify.org", ct)).Trim();
        }
        catch { return "?"; }
    }

    private static string GenerateConfig(ServerInfo server)
    {
        var localSocksPort = GetFreePort();
        var localHttpPort = GetFreePort();

        var outbound = server.Protocol switch
        {
            ProxyProtocol.VlessReality => $$"""
                "type": "vless",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "uuid": "{{server.Uuid}}",
                "flow": "{{server.Flow}}",
                "tls": {
                    "enabled": true,
                    "server_name": "{{server.Sni}}",
                    "utls": { "enabled": true, "fingerprint": "{{server.Fingerprint}}" },
                    "reality": {
                        "enabled": true,
                        "public_key": "{{server.PublicKey}}",
                        "short_id": "{{server.ShortId}}"
                    }
                }
            """,
            ProxyProtocol.VlessWs => $$"""
                "type": "vless",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "uuid": "{{server.Uuid}}",
                "tls": {
                    "enabled": true,
                    "server_name": "{{server.Sni}}",
                    "utls": { "enabled": true, "fingerprint": "chrome" }
                },
                "transport": {
                    "type": "ws",
                    "path": "{{server.Path}}",
                    "headers": { "Host": "{{server.Host}}" }
                }
            """,
            ProxyProtocol.Trojan => $$"""
                "type": "trojan",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "password": "{{server.Password}}",
                "tls": {
                    "enabled": true,
                    "server_name": "{{server.Sni}}",
                    "utls": { "enabled": true, "fingerprint": "chrome" }
                }
            """,
            ProxyProtocol.Hysteria2 => $$"""
                "type": "hysteria2",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "password": "{{server.Password}}",
                "tls": {
                    "enabled": true,
                    "server_name": "{{server.Sni}}"
                }
            """,
            ProxyProtocol.VmessWs => $$"""
                "type": "vmess",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "uuid": "{{server.Uuid}}",
                "alter_id": 0,
                "tls": {
                    "enabled": true,
                    "server_name": "{{server.Sni}}",
                    "utls": { "enabled": true, "fingerprint": "chrome" }
                },
                "transport": {
                    "type": "ws",
                    "path": "{{server.Path}}"
                }
            """,
            ProxyProtocol.Shadowsocks => $$"""
                "type": "shadowsocks",
                "server": "{{server.Host}}",
                "server_port": {{server.Port}},
                "method": "aes-256-gcm",
                "password": "{{server.Password}}"
            """,
            _ => ""
        };

        if (string.IsNullOrEmpty(outbound)) return "{}";

        return $$"""
        {
            "log": { "level": "warn" },
            "inbounds": [
                { "type": "socks", "listen": "127.0.0.1", "listen_port": {{localSocksPort}} },
                { "type": "http", "listen": "127.0.0.1", "listen_port": {{localHttpPort}} }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    {{outbound.Trim()}}
                },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                "rules": [],
                "final": "proxy"
            }
        }
        """;
    }

    private static int GetFreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
