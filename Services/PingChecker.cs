using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class PingChecker
{
    public static async Task<CheckResult> CheckAsync(ServerInfo server, CancellationToken ct = default)
    {
        var result = new CheckResult { Server = server };
        try
        {
            using var ping = new Ping();
            var sw = Stopwatch.StartNew();
            var reply = await ping.SendPingAsync(server.Host, 3000);
            sw.Stop();
            result.PingOk = reply.Status == IPStatus.Success;
            result.PingMs = result.PingOk ? (int)sw.ElapsedMilliseconds : -1;
        }
        catch
        {
            result.PingOk = false;
            result.PingMs = -1;
        }
        return result;
    }

    /// <summary>
    /// Измеряет пинг через активный туннель (после успешной проверки прокси).
    /// Используется в DeepCheckService вместо прямого ICMP к серверу.
    /// </summary>
    public static async Task<int> MeasureThroughProxyAsync(string testUrl, int httpPort, CancellationToken ct = default)
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
            var sw = Stopwatch.StartNew();
            await http.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            sw.Stop();
            return (int)sw.ElapsedMilliseconds;
        }
        catch { return -1; }
    }
}