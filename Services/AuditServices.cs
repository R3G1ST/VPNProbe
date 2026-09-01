using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class IpInfoService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

    public static async Task<IpInfo> GetInfoAsync()
    {
        try
        {
            var json = await _http.GetStringAsync("https://ipwho.is/");
            var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (!r.TryGetProperty("success", out var ok) || !ok.GetBoolean())
                throw new Exception("ipwho.is failed");
            var conn = r.TryGetProperty("connection", out var c) ? c : default;
            var org = conn.TryGetProperty("org", out var orgProp) ? orgProp.GetString() ?? "" : "";
            var asnInt = conn.TryGetProperty("asn", out var asnProp) ? asnProp.GetInt32() : 0;
            var isp = conn.TryGetProperty("isp", out var ispProp) ? ispProp.GetString() ?? "" : "";
            var isHosting = org.Contains("hosting", StringComparison.OrdinalIgnoreCase) ||
                           org.Contains("VPS", StringComparison.OrdinalIgnoreCase) ||
                           org.Contains("server", StringComparison.OrdinalIgnoreCase) ||
                           org.Contains("datacenter", StringComparison.OrdinalIgnoreCase) ||
                           org.Contains("cloud", StringComparison.OrdinalIgnoreCase) ||
                           org.Contains("LeaseWeb", StringComparison.OrdinalIgnoreCase) ||
                           isp.Contains("Hosting", StringComparison.OrdinalIgnoreCase) ||
                           isp.Contains("Datacenter", StringComparison.OrdinalIgnoreCase);
            return new IpInfo
            {
                Ip = r.TryGetProperty("ip", out var ip) ? ip.GetString() ?? "" : "",
                Isp = isp,
                As = asnInt > 0 ? $"AS{asnInt} {org}" : "",
                Country = r.TryGetProperty("country", out var country) ? country.GetString() ?? "" : "",
                City = r.TryGetProperty("city", out var city) ? city.GetString() ?? "" : "",
                Org = org,
                IsVpn = false,
                IsProxy = isHosting,
                IsTor = false
            };
        }
        catch
        {
            try
            {
                var json = await _http.GetStringAsync("http://ip-api.com/json/?fields=status,country,city,isp,org,as,proxy,hosting,query");
                var doc = JsonDocument.Parse(json);
                var r = doc.RootElement;
                if (r.TryGetProperty("status", out var st) && st.GetString() == "success")
                {
                    return new IpInfo
                    {
                        Ip = r.TryGetProperty("query", out var q) ? q.GetString() ?? "" : "",
                        Isp = r.TryGetProperty("isp", out var isp) ? isp.GetString() ?? "" : "",
                        As = r.TryGetProperty("as", out var asProp) ? asProp.GetString() ?? "" : "",
                        Country = r.TryGetProperty("country", out var c) ? c.GetString() ?? "" : "",
                        City = r.TryGetProperty("city", out var city) ? city.GetString() ?? "" : "",
                        Org = r.TryGetProperty("org", out var org) ? org.GetString() ?? "" : "",
                        IsProxy = r.TryGetProperty("proxy", out var proxy) && proxy.GetBoolean(),
                        IsVpn = r.TryGetProperty("hosting", out var hosting) && hosting.GetBoolean()
                    };
                }
                throw new Exception("ip-api failed");
            }
            catch
            {
                try
                {
                    var json = await _http.GetStringAsync("https://api.ipify.org?format=json");
                    var doc = JsonDocument.Parse(json);
                    return new IpInfo { Ip = doc.RootElement.GetProperty("ip").GetString() ?? "" };
                }
                catch { return new IpInfo(); }
            }
        }
    }
}

public enum DpiBlockType { None, TlsRst, TcpRst, TlsHandshake, TcpDrop16KB, Timeout, Refused, Error }

public static class DpiAuditService
{
    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(8),
        DefaultRequestHeaders = { { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" } }
    };

    private static readonly string[] TestDomains = new[]
    {
        "telegram.org", "rutracker.org", "linkedin.com", "discord.com",
        "twitch.tv", "reddit.com", "twitter.com", "facebook.com",
        "youtube.com", "instagram.com", "tiktok.com", "vk.com",
        "github.com", "google.com", "netflix.com", "spotify.com"
    };

    public static event Action<string, int, int>? OnDomainProgress;

    public static async Task<DpiDetectionResult> RunAsync(CancellationToken ct = default)
    {
        var result = new DpiDetectionResult();
        int blocked = 0;
        int idx = 0;
        var blockCounts = new Dictionary<DpiBlockType, int>();

        foreach (var domain in TestDomains)
        {
            if (ct.IsCancellationRequested) break;
            idx++;
            OnDomainProgress?.Invoke(domain, idx, TestDomains.Length);

            var (blockType, detail) = await ProbeDomainFull(domain, ct);
            if (blockType != DpiBlockType.None)
            {
                blocked++;
                result.BlockedDomains.Add(domain);
                if (!blockCounts.ContainsKey(blockType)) blockCounts[blockType] = 0;
                blockCounts[blockType]++;
                if (blockType == DpiBlockType.TlsRst || blockType == DpiBlockType.TlsHandshake)
                    result.TlsBlocking = true;
                if (blockType == DpiBlockType.TcpDrop16KB || blockType == DpiBlockType.TcpRst)
                    result.Tcp16KBBlocking = true;
                if (blockType == DpiBlockType.Refused)
                    result.HttpBlocking = true;
            }
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var resp = await _http.GetAsync("http://neverssl.com/", cts.Token);
            if (resp.StatusCode == HttpStatusCode.Forbidden)
                result.HttpBlocking = true;
        }
        catch { }

        try
        {
            using var udp = new UdpClient();
            var query = BuildDnsQuery("google.com");
            await udp.SendAsync(query, query.Length, "8.8.8.8", 53);
            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts2.CancelAfter(TimeSpan.FromSeconds(3));
            var result2 = await udp.ReceiveAsync(cts2.Token);
            if (result2.Buffer.Length < 12) result.DnsBlocking = true;
        }
        catch { result.DnsBlocking = true; }

        var parts = new List<string>();
        if (blockCounts.TryGetValue(DpiBlockType.TlsRst, out var c1) && c1 > 0) parts.Add($"TLS RST: {c1}");
        if (blockCounts.TryGetValue(DpiBlockType.TcpRst, out var c2) && c2 > 0) parts.Add($"TCP RST: {c2}");
        if (blockCounts.TryGetValue(DpiBlockType.TcpDrop16KB, out var c3) && c3 > 0) parts.Add($"TCP 16KB: {c3}");
        if (blockCounts.TryGetValue(DpiBlockType.TlsHandshake, out var c4) && c4 > 0) parts.Add($"TLS block: {c4}");
        if (blockCounts.TryGetValue(DpiBlockType.Timeout, out var c5) && c5 > 0) parts.Add($"Timeout: {c5}");
        if (blockCounts.TryGetValue(DpiBlockType.Refused, out var c6) && c6 > 0) parts.Add($"Refused: {c6}");
        result.Method = parts.Count > 0 ? string.Join(", ", parts) : "No blocking detected";

        return result;
    }

    private static async Task<(DpiBlockType type, string detail)> ProbeDomainFull(string domain, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                UseCookies = false,
                AllowAutoRedirect = false
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            client.DefaultRequestHeaders.Add("Connection", "close");

            var resp = await client.GetAsync($"https://{domain}/", cts.Token);
            return (DpiBlockType.None, "");
        }
        catch (TaskCanceledException)
        {
            try
            {
                using var tcp = new TcpClient();
                var connectTask = tcp.ConnectAsync(domain, 443, ct).AsTask();
                if (await Task.WhenAny(connectTask, Task.Delay(3000, ct)) != connectTask)
                    return (DpiBlockType.Timeout, "TCP connect timeout");
                return (DpiBlockType.TlsHandshake, "TLS handshake timeout (DPI)");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return (DpiBlockType.Refused, "Connection refused");
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                return (DpiBlockType.TcpRst, "TCP RST during connect");
            }
            catch { return (DpiBlockType.Timeout, "Timeout"); }
        }
        catch (HttpRequestException ex)
        {
            if (ex.InnerException is SocketException se)
            {
                if (se.SocketErrorCode == SocketError.ConnectionReset)
                    return (DpiBlockType.TlsRst, "TLS RST (SNI block)");
                if (se.SocketErrorCode == SocketError.ConnectionRefused)
                    return (DpiBlockType.Refused, "Connection refused");
            }
            if (ex.InnerException is IOException)
                return (DpiBlockType.TlsRst, "TLS RST during handshake");
            return (DpiBlockType.Error, ex.Message);
        }
        catch (IOException)
        {
            return (DpiBlockType.TlsRst, "TLS RST (SNI block)");
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            return (DpiBlockType.TcpRst, "TCP RST");
        }
        catch
        {
            return (DpiBlockType.Error, "Unknown error");
        }
    }

    internal static byte[] BuildDnsQuery(string domain)
    {
        var ms = new MemoryStream();
        var rng = new Random();
        ms.Write(new byte[] { (byte)(rng.Next(256)), (byte)(rng.Next(256)), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 12);
        foreach (var part in domain.Split('.'))
        {
            ms.WriteByte((byte)part.Length);
            ms.Write(Encoding.ASCII.GetBytes(part), 0, part.Length);
        }
        ms.Write(new byte[] { 0, 1, 0, 1 }, 0, 4);
        return ms.ToArray();
    }
}

public static class SpeedAuditService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<SpeedResult> RunAsync(CancellationToken ct = default)
    {
        var result = new SpeedResult();

        try
        {
            var servers = await _http.GetStringAsync("https://www.speedtest.net/api/js/servers?engine=ip&limit=5", ct);
            var doc = JsonDocument.Parse(servers);
            if (doc.RootElement.GetArrayLength() > 0)
            {
                var server = doc.RootElement[0];
                result.Server = server.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var url = server.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                if (!string.IsNullOrEmpty(url))
                {
                    try
                    {
                        var sw = Stopwatch.StartNew();
                        var dlBytes = await _http.GetByteArrayAsync($"{url}random2000x2000.jpg", ct);
                        sw.Stop();
                        var seconds = sw.Elapsed.TotalSeconds;
                        result.DownloadMbps = seconds > 0.001 ? Math.Round(dlBytes.Length * 8.0 / 1_000_000 / seconds, 1) : 0;
                    }
                    catch { }
                }
            }
        }
        catch { }

        if (result.DownloadMbps <= 0)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var dlBytes = await _http.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=10000000", ct);
                sw.Stop();
                var seconds = sw.Elapsed.TotalSeconds;
                result.DownloadMbps = seconds > 0.001 ? Math.Round(dlBytes.Length * 8.0 / 1_000_000 / seconds, 1) : 0;
                result.Server = "Cloudflare";
            }
            catch { }
        }

        try
        {
            using var ping = new System.Net.NetworkInformation.Ping();
            var reply = await ping.SendPingAsync("8.8.8.8", 3000);
            result.PingMs = reply.Status == System.Net.NetworkInformation.IPStatus.Success ? (int)reply.RoundtripTime : 0;
        }
        catch { }

        try
        {
            var pings = new List<int>();
            for (int i = 0; i < 10; i++)
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var reply = await ping.SendPingAsync("8.8.8.8", 2000);
                if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    pings.Add((int)reply.RoundtripTime);
                await Task.Delay(100, ct);
            }
            if (pings.Count > 1)
            {
                var avg = pings.Average();
                result.JitterMs = (int)Math.Sqrt(pings.Select(p => Math.Pow(p - avg, 2)).Average());
            }
        }
        catch { }

        return result;
    }
}

public static class BufferbloatService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<BufferbloatResult> RunAsync(CancellationToken ct = default)
    {
        var result = new BufferbloatResult();
        var pings = new List<int>();

        try
        {
            for (int i = 0; i < 5; i++)
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var reply = await ping.SendPingAsync("8.8.8.8", 3000);
                if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    pings.Add((int)reply.RoundtripTime);
            }
            result.IdlePingMs = pings.Count > 0 ? (int)pings.Average() : 0;
        }
        catch { }

        try
        {
            var tasks = new List<Task>();
            for (int i = 0; i < 3; i++)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try { await _http.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=50000000", ct); }
                    catch { }
                }, ct));
            }

            var loadedPings = new List<int>();
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 8000 && !ct.IsCancellationRequested)
            {
                try
                {
                    using var ping = new System.Net.NetworkInformation.Ping();
                    var reply = await ping.SendPingAsync("8.8.8.8", 2000);
                    if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                        loadedPings.Add((int)reply.RoundtripTime);
                }
                catch { }
                await Task.Delay(500, ct);
            }
            result.LoadedPingMs = loadedPings.Count > 0 ? (int)loadedPings.Average() : result.IdlePingMs;

            await Task.WhenAll(tasks);
        }
        catch { }

        result.LoadedPingMs = Math.Max(result.LoadedPingMs, result.IdlePingMs);
        var increase = result.IdlePingMs > 0 ? (double)(result.LoadedPingMs - result.IdlePingMs) / result.IdlePingMs : 0;
        result.Grade = increase < 0.3 ? "A+" : increase < 0.7 ? "A" : increase < 1.5 ? "B" : increase < 3.0 ? "C" : increase < 5.0 ? "D" : "F";

        return result;
    }
}

public static class DnsAuditService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

    private static readonly (string Name, string Ip, bool SupportsDoH)[] Resolvers = new[]
    {
        ("Google", "8.8.8.8", true),
        ("Cloudflare", "1.1.1.1", true),
        ("AdGuard", "94.140.14.14", true),
        ("Quad9", "9.9.9.9", true),
        ("OpenDNS", "208.67.222.222", true),
        ("CleanBrowsing", "185.228.168.9", true),
        ("Yandex", "77.88.8.8", false),
    };

    private static readonly string[] DohDomains = { "google.com", "telegram.org", "rutracker.org" };

    public static async Task<List<DnsResult>> RunAsync(CancellationToken ct = default)
    {
        var results = new List<DnsResult>();
        var dohTruth = await GetDohTruth(ct);

        foreach (var (name, ip, doh) in Resolvers)
        {
            if (ct.IsCancellationRequested) break;
            var r = new DnsResult { Resolver = name, SupportsDoH = doh };

            try
            {
                var sw = Stopwatch.StartNew();
                var query = BuildDnsQuery("google.com");
                using var udp = new UdpClient();
                await udp.SendAsync(query, query.Length, ip, 53);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                var result = await udp.ReceiveAsync(cts.Token);
                sw.Stop();
                r.ResponseMs = (int)sw.ElapsedMilliseconds;
                r.IsEncrypted = false;

                if (dohTruth != null && result.Buffer.Length > 12)
                {
                    var udpIps = ParseDnsResponseIps(result.Buffer);
                    if (udpIps.Count > 0 && !udpIps.Any(uip => dohTruth.Contains(uip)))
                        r.IsHijacked = true;
                }
            }
            catch (TaskCanceledException) { r.ResponseMs = -1; }
            catch { r.ResponseMs = -1; }
            results.Add(r);
        }

        try
        {
            var sw = Stopwatch.StartNew();
            using var req = new HttpRequestMessage(HttpMethod.Get, "https://cloudflare-dns.com/dns-query?name=google.com&type=A");
            req.Headers.Add("accept", "application/dns-json");
            var resp = await _http.SendAsync(req, ct);
            sw.Stop();
            var body = await resp.Content.ReadAsStringAsync(ct);
            var doc = JsonDocument.Parse(body);
            var answerCount = doc.RootElement.TryGetProperty("Answer", out var ans) ? ans.GetArrayLength() : 0;
            results.Insert(0, new DnsResult
            {
                Resolver = "Cloudflare DoH",
                ResponseMs = (int)sw.ElapsedMilliseconds,
                IsEncrypted = true,
                SupportsDoH = true,
                IsHijacked = answerCount == 0
            });
        }
        catch { }

        return results;
    }

    private static async Task<HashSet<string>?> GetDohTruth(CancellationToken ct)
    {
        try
        {
            var allIps = new HashSet<string>();
            foreach (var domain in DohDomains)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get,
                    $"https://cloudflare-dns.com/dns-query?name={domain}&type=A");
                req.Headers.Add("accept", "application/dns-json");
                var resp = await _http.SendAsync(req, ct);
                var body = await resp.Content.ReadAsStringAsync(ct);
                var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("Answer", out var ans))
                {
                    foreach (var a in ans.EnumerateArray())
                    {
                        if (a.TryGetProperty("data", out var data))
                            allIps.Add(data.GetString() ?? "");
                    }
                }
            }
            return allIps.Count > 0 ? allIps : null;
        }
        catch { return null; }
    }

    private static List<string> ParseDnsResponseIps(byte[] buffer)
    {
        var ips = new List<string>();
        if (buffer.Length < 12) return ips;
        var ancount = (buffer[6] << 8) | buffer[7];
        int offset = 12;
        try
        {
            while (offset < buffer.Length && buffer[offset] != 0)
            {
                if ((buffer[offset] & 0xC0) == 0xC0) { offset += 2; break; }
                offset += buffer[offset] + 1;
            }
            if (offset < buffer.Length && buffer[offset] == 0) offset++;
            offset += 4;
            for (int i = 0; i < ancount && offset + 10 <= buffer.Length; i++)
            {
                if ((buffer[offset] & 0xC0) == 0xC0) offset += 2;
                else { while (offset < buffer.Length && buffer[offset] != 0) offset += buffer[offset] + 1; offset++; }
                var rtype = (buffer[offset] << 8) | buffer[offset + 1];
                var rdlen = (buffer[offset + 8] << 8) | buffer[offset + 9];
                offset += 10;
                if (rtype == 1 && rdlen == 4 && offset + 4 <= buffer.Length)
                    ips.Add($"{buffer[offset]}.{buffer[offset + 1]}.{buffer[offset + 2]}.{buffer[offset + 3]}");
                offset += rdlen;
            }
        }
        catch { }
        return ips;
    }

    internal static byte[] BuildDnsQuery(string domain)
    {
        var ms = new MemoryStream();
        var rng = new Random();
        ms.Write(new byte[] { (byte)(rng.Next(256)), (byte)(rng.Next(256)), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 12);
        foreach (var part in domain.Split('.'))
        {
            ms.WriteByte((byte)part.Length);
            ms.Write(Encoding.ASCII.GetBytes(part), 0, part.Length);
        }
        ms.Write(new byte[] { 0, 1, 0, 1 }, 0, 4);
        return ms.ToArray();
    }
}

public static class GeoBlockService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    private static readonly (string Service, string Url, string Category)[] Sites = new[]
    {
        ("Telegram", "https://web.telegram.org", "Мессенджеры"),
        ("Discord", "https://discord.com/app", "Мессенджеры"),
        ("YouTube", "https://www.youtube.com", "Видео"),
        ("Netflix", "https://www.netflix.com/browse", "Стриминг"),
        ("Twitch", "https://www.twitch.tv", "Стриминг"),
        ("Spotify", "https://open.spotify.com", "Музыка"),
        ("Twitter/X", "https://x.com", "Соцсети"),
        ("Reddit", "https://www.reddit.com/.rss", "Соцсети"),
        ("TikTok", "https://www.tiktok.com", "Соцсети"),
        ("Instagram", "https://www.instagram.com", "Соцсети"),
        ("Facebook", "https://www.facebook.com", "Соцсети"),
        ("VK", "https://vk.com", "Соцсети"),
        ("LinkedIn", "https://www.linkedin.com", "Профессиональные"),
        ("RuTracker", "https://rutracker.org", "Торренты"),
        ("GitHub", "https://github.com", "Разработка"),
        ("BBC", "https://www.bbc.com", "Новости"),
        ("CNN", "https://www.cnn.com", "Новости"),
        ("RBC", "https://www.rbc.ru", "Новости"),
        ("Amazon", "https://www.amazon.com", "Магазины"),
        ("Steam", "https://store.steampowered.com", "Игры"),
    };

    public static async Task<List<GeoBlockResult>> RunAsync(CancellationToken ct = default)
    {
        var results = new List<GeoBlockResult>();

        foreach (var (service, url, category) in Sites)
        {
            if (ct.IsCancellationRequested) break;
            var r = new GeoBlockResult { Service = service, Category = category };
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Head, url);
                req.Headers.Add("User-Agent", "Mozilla/5.0");
                var resp = await _http.SendAsync(req, ct);
                r.Blocked = resp.StatusCode == HttpStatusCode.Forbidden ||
                            resp.StatusCode == HttpStatusCode.ServiceUnavailable ||
                            (int)resp.StatusCode == 451 ||
                            ((int)resp.StatusCode >= 500 && (int)resp.StatusCode < 600);
                r.Method = $"HTTP {(int)resp.StatusCode}";
            }
            catch (HttpRequestException ex)
            {
                r.Blocked = true;
                r.Method = ex.StatusCode.HasValue ? $"HTTP {(int)ex.StatusCode}" : "Connection refused";
            }
            catch (TaskCanceledException) { r.Blocked = true; r.Method = "Timeout"; }
            catch { r.Blocked = true; r.Method = "Error"; }
            results.Add(r);
        }

        return results;
    }
}
