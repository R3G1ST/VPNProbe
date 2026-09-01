using System;
using System.Diagnostics;
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
}
