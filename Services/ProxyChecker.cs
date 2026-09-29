using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class ProxyChecker
{
    public static readonly string SingBoxPath = FindSingBox();

    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static string FindSingBox()
    {
        var candidates = new[]
        {
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sing-box.exe"),
            @"C:\sing-box\sing-box.exe",
            @"C:\Tools\sing-box.exe",
            @"C:\Program Files\sing-box\sing-box.exe",
            @"C:\Program Files (x86)\sing-box\sing-box.exe",
            @"D:\sing-box\sing-box.exe",
            @"D:\Tools\sing-box.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "sing-box", "sing-box.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "sing-box", "sing-box.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "sing-box", "sing-box.exe"),
            @"C:\Program Files\VPNProbe\sing-box.exe",
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
        Process? process = null;
        try
        {
            var (config, port) = GenerateConfigWithPort(server);
            await File.WriteAllTextAsync(configPath, config, ct);

            process = new Process();
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

            if (process.HasExited)
            {
                result.Error = "sing-box exited early";
                return result;
            }

            var testUrl = "http://cp.cloudflare.com/";
            var success = await TestThroughProxy(testUrl, port, ct);

            if (success)
            {
                result.ProxyOk = true;
                var ip = await GetExternalIpAsync(port, ct);
                result.ProxyIp = ip;
            }
        }
        catch (OperationCanceledException) { result.Error = "Timeout"; }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            try { process?.Kill(); } catch { }
            try { process?.Dispose(); } catch { }
            try { File.Delete(configPath); } catch { }
        }
        return result;
    }

    private static object BuildOutbound(ServerInfo server)
    {
        var baseOut = new System.Collections.Generic.Dictionary<string, object>
        {
            ["server"] = server.Host,
            ["server_port"] = server.Port
        };

        return server.Protocol switch
        {
            ProxyProtocol.VlessReality => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "vless",
                ["tag"] = "proxy",
                ["uuid"] = server.Uuid,
                ["flow"] = server.Flow,
                ["tls"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = server.Sni,
                    ["utls"] = new System.Collections.Generic.Dictionary<string, object>
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = server.Fingerprint
                    },
                    ["reality"] = new System.Collections.Generic.Dictionary<string, object>
                    {
                        ["enabled"] = true,
                        ["public_key"] = server.PublicKey,
                        ["short_id"] = server.ShortId
                    }
                }
            },
            ProxyProtocol.VlessWs => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "vless",
                ["tag"] = "proxy",
                ["uuid"] = server.Uuid,
                ["tls"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = server.Sni,
                    ["utls"] = new System.Collections.Generic.Dictionary<string, object>
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = server.Fingerprint
                    }
                },
                ["transport"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["type"] = "ws",
                    ["path"] = server.Path,
                    ["headers"] = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["Host"] = server.HostHeader
                    }
                }
            },
            ProxyProtocol.VmessWs => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "vmess",
                ["tag"] = "proxy",
                ["uuid"] = server.Uuid,
                ["security"] = "auto",
                ["tls"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = server.Sni,
                    ["utls"] = new System.Collections.Generic.Dictionary<string, object>
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = server.Fingerprint
                    }
                },
                ["transport"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["type"] = "ws",
                    ["path"] = server.Path,
                    ["headers"] = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["Host"] = server.HostHeader
                    }
                }
            },
            ProxyProtocol.Trojan => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "trojan",
                ["tag"] = "proxy",
                ["password"] = server.Password,
                ["tls"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = server.Sni,
                    ["utls"] = new System.Collections.Generic.Dictionary<string, object>
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = server.Fingerprint
                    }
                }
            },
            ProxyProtocol.Hysteria2 => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "hysteria2",
                ["tag"] = "proxy",
                ["password"] = server.Password,
                ["tls"] = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["enabled"] = true,
                    ["server_name"] = server.Sni,
                    ["insecure"] = true
                }
            },
            ProxyProtocol.Shadowsocks => new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "shadowsocks",
                ["tag"] = "proxy",
                ["server"] = server.Host,
                ["server_port"] = server.Port,
                ["method"] = "aes-256-gcm",
                ["password"] = server.Password
            },
            _ => new System.Collections.Generic.Dictionary<string, object>()
        };
    }

    public static (string config, int port) GenerateConfigWithPort(ServerInfo server)
    {
        var port = GetFreePort();
        var outbound = BuildOutbound(server);

        var config = new System.Collections.Generic.Dictionary<string, object>
        {
            ["log"] = new System.Collections.Generic.Dictionary<string, object> { ["level"] = "warn" },
            ["inbounds"] = new[] { new System.Collections.Generic.Dictionary<string, object>
            {
                ["type"] = "mixed",
                ["listen"] = "127.0.0.1",
                ["listen_port"] = port
            }},
            ["outbounds"] = new object[]
            {
                outbound,
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "direct", ["tag"] = "direct" },
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "block", ["tag"] = "block" }
            },
            ["route"] = new System.Collections.Generic.Dictionary<string, object>
            {
                ["rules"] = Array.Empty<object>(),
                ["final"] = "proxy"
            }
        };

        return (JsonSerializer.Serialize(config, _jsonOpts), port);
    }

    private static async Task<bool> TestThroughProxy(string url, int httpPort, CancellationToken ct)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{httpPort}"),
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler);
            http.Timeout = TimeSpan.FromSeconds(8);
            var resp = await http.GetAsync(url, ct);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private static async Task<string> GetExternalIpAsync(int httpPort, CancellationToken ct)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{httpPort}"),
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler);
            http.Timeout = TimeSpan.FromSeconds(5);
            return (await http.GetStringAsync("https://api.ipify.org", ct)).Trim();
        }
        catch { return "?"; }
    }

    public static string GenerateConfig(ServerInfo server)
    {
        var localSocksPort = GetFreePort();
        var localHttpPort = GetFreePort();
        var outbound = BuildOutbound(server);

        // Override tags and listen for this public config method
        if (outbound is System.Collections.Generic.Dictionary<string, object> dict)
        {
            dict["tag"] = "proxy";
        }

        return JsonSerializer.Serialize(new System.Collections.Generic.Dictionary<string, object>
        {
            ["log"] = new System.Collections.Generic.Dictionary<string, object> { ["level"] = "warn" },
            ["inbounds"] = new[] {
                new System.Collections.Generic.Dictionary<string, object>
                { ["type"] = "socks", ["listen"] = "127.0.0.1", ["listen_port"] = localSocksPort },
                new System.Collections.Generic.Dictionary<string, object>
                { ["type"] = "http", ["listen"] = "127.0.0.1", ["listen_port"] = localHttpPort }
            },
            ["outbounds"] = new object[]
            {
                outbound,
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "direct", ["tag"] = "direct" },
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "block", ["tag"] = "block" }
            },
            ["route"] = new System.Collections.Generic.Dictionary<string, object>
            {
                ["rules"] = Array.Empty<object>(),
                ["final"] = "proxy"
            }
        }, _jsonOpts);
    }

    public static string GenerateConfigOnPorts(ServerInfo server, int socksPort, int httpPort)
    {
        var outbound = BuildOutbound(server);

        return JsonSerializer.Serialize(new System.Collections.Generic.Dictionary<string, object>
        {
            ["log"] = new System.Collections.Generic.Dictionary<string, object> { ["level"] = "warn" },
            ["inbounds"] = new[] {
                new System.Collections.Generic.Dictionary<string, object>
                { ["type"] = "socks", ["listen"] = "127.0.0.1", ["listen_port"] = socksPort },
                new System.Collections.Generic.Dictionary<string, object>
                { ["type"] = "http", ["listen"] = "127.0.0.1", ["listen_port"] = httpPort }
            },
            ["outbounds"] = new object[]
            {
                outbound,
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "direct", ["tag"] = "direct" },
                new System.Collections.Generic.Dictionary<string, object> { ["type"] = "block", ["tag"] = "block" }
            },
            ["route"] = new System.Collections.Generic.Dictionary<string, object>
            {
                ["rules"] = Array.Empty<object>(),
                ["final"] = "proxy"
            }
        }, _jsonOpts);
    }

    public static int GetFreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}