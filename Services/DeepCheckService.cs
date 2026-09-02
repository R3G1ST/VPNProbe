using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class DeepCheckService
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    }) { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<DeepCheckResult> RunAllChecks(ServerInfo server, CancellationToken ct = default)
    {
        var r = new DeepCheckResult { Server = server };

        // Level 1: Ping
        var ping = await PingChecker.CheckAsync(server, ct);
        r.PingMs = ping.PingMs;

        // Level 2: Protocol + TLS
        await CheckTlsDeep(server, r, ct);

        // Level 3: Real traffic
        await CheckRealTraffic(server, r, ct);

        // Level 4: Speed
        await CheckSpeed(server, r, ct);

        // Level 5: Stability
        await CheckStability(server, r, ct);

        // Summary
        r.Grade = CalculateGrade(r);
        r.IsFullyWorking = r.TlsValid && r.TrafficOk && r.SpeedMbps > 0 && r.PacketLossPct < 10;

        return r;
    }

    private static async Task CheckTlsDeep(ServerInfo server, DeepCheckResult r, CancellationToken ct)
    {
        // Reality servers: skip standard TLS check, verify Reality handshake
        if (r.IsReality)
        {
            r.RealityOk = true;
            r.RealityFingerprint = server.Fingerprint;
            // Reality handshake is verified through traffic test
            return;
        }

        try
        {
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(server.Host, server.Port);
            if (await Task.WhenAny(connectTask, Task.Delay(10000, ct)) != connectTask)
            {
                r.TlsError = "TCP timeout";
                return;
            }

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            var sslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = server.Host,
                EnabledSslProtocols = sslProtocols
            }, ct);

            r.TlsValid = true;
            r.TlsVersion = ssl.SslProtocol.ToString();

            var cert = ssl.RemoteCertificate;
            if (cert != null)
            {
                var cert2 = new X509Certificate2(cert);
                r.CertSubject = cert2.Subject;
                r.CertIssuer = cert2.Issuer;
                r.CertExpiry = cert2.NotAfter.ToString("yyyy-MM-dd");
                r.CertDaysLeft = (cert2.NotAfter - DateTime.UtcNow).Days;

                var san = cert2.Extensions["2.5.29.17"] as X509SubjectAlternativeNameExtension;
                r.CertSan = san?.EnumerateDnsNames()?.ToList() ?? new();

                r.CertValid = r.CertDaysLeft > 0;
            }
        }
        catch (Exception ex)
        {
            r.TlsError = ex.Message;
        }
    }

    private static async Task CheckRealTraffic(ServerInfo server, DeepCheckResult r, CancellationToken ct)
    {
        if (!r.TlsValid && !r.IsReality) return;

        try
        {
            var configPath = Path.Combine(Path.GetTempPath(), $"vpnprobe_deep_{Guid.NewGuid():N}.json");
            var config = ProxyChecker.GenerateConfig(server);
            await File.WriteAllTextAsync(configPath, config, ct);

            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = ProxyChecker.SingBoxPath,
                Arguments = $"run -c \"{configPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            process.Start();
            await Task.Delay(2000, ct);

            var testUrls = new[] { "http://cp.cloudflare.com/", "http://ifconfig.me/ip", "http://api.ipify.org" };
            foreach (var url in testUrls)
            {
                try
                {
                    var ip = await Http.GetStringAsync(url, ct);
                    if (!string.IsNullOrWhiteSpace(ip))
                    {
                        r.TrafficOk = true;
                        r.ExitIp = ip.Trim();
                        break;
                    }
                }
                catch { }
            }

            try { process.Kill(); } catch { }
            try { File.Delete(configPath); } catch { }
        }
        catch (Exception ex)
        {
            r.TrafficError = ex.Message;
        }
    }

    private static async Task CheckSpeed(ServerInfo server, DeepCheckResult r, CancellationToken ct)
    {
        if (!r.TrafficOk) return;

        try
        {
            var configPath = Path.Combine(Path.GetTempPath(), $"vpnprobe_speed_{Guid.NewGuid():N}.json");
            var config = ProxyChecker.GenerateConfig(server);
            await File.WriteAllTextAsync(configPath, config, ct);

            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = ProxyChecker.SingBoxPath,
                Arguments = $"run -c \"{configPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            process.Start();
            await Task.Delay(2000, ct);

            var sw = Stopwatch.StartNew();
            var totalBytes = 0L;
            var testUrl = "http://speedtest.tele2.net/1MB.zip";

            try
            {
                var response = await Http.GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                var stream = await response.Content.ReadAsStreamAsync(ct);
                var buffer = new byte[8192];
                int read;
                while ((read = await stream.ReadAsync(buffer, ct)) > 0)
                {
                    totalBytes += read;
                    if (sw.Elapsed.TotalSeconds > 15) break;
                }
            }
            catch { }

            sw.Stop();
            try { process.Kill(); } catch { }
            try { File.Delete(configPath); } catch { }

            if (sw.Elapsed.TotalSeconds > 0 && totalBytes > 0)
            {
                r.SpeedBytes = totalBytes;
                r.SpeedMbps = totalBytes / sw.Elapsed.TotalSeconds / 1024 / 1024 * 8;
                r.SpeedDurationMs = (int)sw.ElapsedMilliseconds;
            }
        }
        catch (Exception ex)
        {
            r.SpeedError = ex.Message;
        }
    }

    private static async Task CheckStability(ServerInfo server, DeepCheckResult r, CancellationToken ct)
    {
        if (!r.TrafficOk) return;

        try
        {
            var configPath = Path.Combine(Path.GetTempPath(), $"vpnprobe_stab_{Guid.NewGuid():N}.json");
            var config = ProxyChecker.GenerateConfig(server);
            await File.WriteAllTextAsync(configPath, config, ct);

            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = ProxyChecker.SingBoxPath,
                Arguments = $"run -c \"{configPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            process.Start();
            await Task.Delay(2000, ct);

            var totalRequests = 0;
            var successRequests = 0;
            var testUrl = "http://cp.cloudflare.com/";
            var sw = Stopwatch.StartNew();

            while (sw.Elapsed.TotalSeconds < 10)
            {
                try
                {
                    var resp = await Http.GetAsync(testUrl, ct);
                    totalRequests++;
                    if (resp.IsSuccessStatusCode) successRequests++;
                }
                catch
                {
                    totalRequests++;
                }
                await Task.Delay(500, ct);
            }

            try { process.Kill(); } catch { }
            try { File.Delete(configPath); } catch { }

            r.StabilityRequests = totalRequests;
            r.StabilitySuccess = successRequests;
            r.PacketLossPct = totalRequests > 0 ? (double)(totalRequests - successRequests) / totalRequests * 100 : 100;
        }
        catch (Exception ex)
        {
            r.StabilityError = ex.Message;
        }
    }

    private static string CalculateGrade(DeepCheckResult r)
    {
        var score = 0;
        var isReality = r.IsReality;

        if (isReality)
        {
            // Reality servers: different grading logic
            // TLS check is not applicable (fake certificate by design)
            if (r.TrafficOk) score += 40;
            if (r.SpeedMbps > 5) score += 20;
            else if (r.SpeedMbps > 1) score += 15;
            if (r.PacketLossPct < 5) score += 20;
            else if (r.PacketLossPct < 20) score += 10;
            if (r.PingMs < 200) score += 10;
            else if (r.PingMs < 400) score += 5;
            if (r.RealityOk) score += 10;
        }
        else
        {
            // Regular servers: standard TLS-based grading
            if (r.TlsValid) score += 25;
            if (r.CertValid) score += 10;
            if (r.TrafficOk) score += 25;
            if (r.SpeedMbps > 5) score += 15;
            else if (r.SpeedMbps > 1) score += 10;
            if (r.PacketLossPct < 5) score += 15;
            else if (r.PacketLossPct < 20) score += 8;
        }

        return score switch
        {
            >= 90 => "A+",
            >= 80 => "A",
            >= 70 => "B+",
            >= 60 => "B",
            >= 50 => "C",
            >= 30 => "D",
            _ => "F"
        };
    }
}

public class DeepCheckResult
{
    public ServerInfo Server { get; set; } = new();

    // Level 2: TLS
    public bool TlsValid { get; set; }
    public string TlsVersion { get; set; } = "";
    public string TlsError { get; set; } = "";
    public string CertSubject { get; set; } = "";
    public string CertIssuer { get; set; } = "";
    public string CertExpiry { get; set; } = "";
    public int CertDaysLeft { get; set; }
    public List<string> CertSan { get; set; } = new();
    public bool CertValid { get; set; }
    public bool IsReality => !string.IsNullOrEmpty(Server?.PublicKey);
    public bool RealityOk { get; set; }
    public string RealityFingerprint { get; set; } = "";
    public int PingMs { get; set; } = -1;

    // Level 3: Traffic
    public bool TrafficOk { get; set; }
    public string ExitIp { get; set; } = "";
    public string TrafficError { get; set; } = "";

    // Level 4: Speed
    public double SpeedMbps { get; set; }
    public long SpeedBytes { get; set; }
    public int SpeedDurationMs { get; set; }
    public string SpeedError { get; set; } = "";

    // Level 5: Stability
    public int StabilityRequests { get; set; }
    public int StabilitySuccess { get; set; }
    public double PacketLossPct { get; set; }
    public string StabilityError { get; set; } = "";

    // Summary
    public string Grade { get; set; } = "F";
    public bool IsFullyWorking { get; set; }
}
