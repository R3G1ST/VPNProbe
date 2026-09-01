using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;
using VPNProbe.Services;

namespace VPNProbe.Services;

public static class AuditOrchestrator
{
    public static event Action<string, string>? OnProgress;
    public static event Action<AuditResult>? OnCheckComplete;

    public static async Task<List<AuditResult>> RunFullAuditAsync(CancellationToken ct = default)
    {
        var results = new List<AuditResult>();

        var ipInfo = await RunCheck("IP Info", "Сеть", ct, async () =>
        {
            var info = await IpInfoService.GetInfoAsync();
            var r = new AuditResult { Name = "IP Info", Category = "Сеть" };
            r.Checks.Add(new AuditCheck { Name = "IP", Value = info.Ip, Passed = !string.IsNullOrEmpty(info.Ip) });
            r.Checks.Add(new AuditCheck { Name = "ISP", Value = info.Isp, Passed = !string.IsNullOrEmpty(info.Isp) });
            r.Checks.Add(new AuditCheck { Name = "ASN", Value = info.As, Passed = !string.IsNullOrEmpty(info.As) });
            r.Checks.Add(new AuditCheck { Name = "Страна", Value = info.Country, Passed = !string.IsNullOrEmpty(info.Country) });
            r.Checks.Add(new AuditCheck { Name = "Город", Value = info.City, Passed = !string.IsNullOrEmpty(info.City) });
            r.Checks.Add(new AuditCheck { Name = "VPN", Value = info.IsVpn ? "Да" : "Нет", Passed = !info.IsVpn, Severity = info.IsVpn ? "warning" : "info" });
            r.Checks.Add(new AuditCheck { Name = "Proxy/Hosting", Value = info.IsProxy ? "Да (VPS/Хостинг)" : "Нет", Passed = !info.IsProxy, Severity = info.IsProxy ? "warning" : "info" });
            r.Checks.Add(new AuditCheck { Name = "Tor", Value = info.IsTor ? "Да" : "Нет", Passed = !info.IsTor, Severity = info.IsTor ? "warning" : "info" });
            r.Score = info.IsVpn || info.IsProxy || info.IsTor ? 70 : 100;
            r.Grade = r.Score >= 90 ? "A+" : r.Score >= 80 ? "A" : r.Score >= 70 ? "B" : r.Score >= 60 ? "C" : "F";
            r.Status = "Готово";
            return r;
        });
        results.Add(ipInfo);
        OnCheckComplete?.Invoke(ipInfo);

        var dpi = await RunCheck("DPI Детекция", "Цензура", ct, async () =>
        {
            Action<string, int, int>? onDomain = (domain, cur, total) =>
                OnProgress?.Invoke("DPI Детекция", $"TLS probe [{cur}/{total}]: {domain}");
            DpiAuditService.OnDomainProgress += onDomain;
            DpiDetectionResult det;
            try { det = await DpiAuditService.RunAsync(ct); }
            finally { DpiAuditService.OnDomainProgress -= onDomain; }
            var r = new AuditResult { Name = "DPI Детекция", Category = "Цензура" };
            int issues = 0;
            if (det.TlsBlocking) { issues++; r.Checks.Add(new AuditCheck { Name = "TLS блокировка", Value = "Обнаружена", Passed = false, Severity = "critical" }); }
            else r.Checks.Add(new AuditCheck { Name = "TLS блокировка", Value = "Нет", Passed = true });
            if (det.Tcp16KBBlocking) { issues++; r.Checks.Add(new AuditCheck { Name = "TCP 16KB дроп", Value = "Обнаружен", Passed = false, Severity = "critical" }); }
            else r.Checks.Add(new AuditCheck { Name = "TCP 16KB дроп", Value = "Нет", Passed = true });
            if (det.HttpBlocking) { issues++; r.Checks.Add(new AuditCheck { Name = "HTTP блокировка", Value = "Обнаружена", Passed = false, Severity = "warning" }); }
            else r.Checks.Add(new AuditCheck { Name = "HTTP блокировка", Value = "Нет", Passed = true });
            if (det.DnsBlocking) { issues++; r.Checks.Add(new AuditCheck { Name = "DNS блокировка", Value = "Обнаружена", Passed = false, Severity = "critical" }); }
            else r.Checks.Add(new AuditCheck { Name = "DNS блокировка", Value = "Нет", Passed = true });
            r.Checks.Add(new AuditCheck { Name = "Заблокировано доменов", Value = $"{det.BlockedDomains.Count}/16", Passed = det.BlockedDomains.Count == 0 });
            r.Score = Math.Max(0, 100 - (issues * 25) - (det.BlockedDomains.Count * 3));
            r.Grade = r.Score >= 90 ? "A+" : r.Score >= 80 ? "A" : r.Score >= 70 ? "B" : r.Score >= 60 ? "C" : r.Score >= 40 ? "D" : "F";
            r.Status = "Готово";
            r.Details = det.Method;
            return r;
        });
        results.Add(dpi);
        OnCheckComplete?.Invoke(dpi);

        var speed = await RunCheck("Скорость", "Производительность", ct, async () =>
        {
            var spd = await SpeedAuditService.RunAsync(ct);
            var r = new AuditResult { Name = "Скорость", Category = "Производительность" };
            r.Checks.Add(new AuditCheck { Name = "Download", Value = $"{spd.DownloadMbps} Mbps", Passed = spd.DownloadMbps > 10 });
            r.Checks.Add(new AuditCheck { Name = "Upload", Value = $"{spd.UploadMbps} Mbps", Passed = false, Severity = "info" });
            r.Checks.Add(new AuditCheck { Name = "Ping", Value = $"{spd.PingMs}ms", Passed = spd.PingMs < 50 });
            r.Checks.Add(new AuditCheck { Name = "Jitter", Value = $"{spd.JitterMs}ms", Passed = spd.JitterMs < 10 });
            r.Checks.Add(new AuditCheck { Name = "Сервер", Value = spd.Server, Passed = true });
            double score = 100;
            if (spd.DownloadMbps <= 0) score -= 40;
            else if (spd.DownloadMbps < 10) score -= 20;
            else if (spd.DownloadMbps < 50) score -= 10;
            if (spd.PingMs > 100) score -= 30;
            else if (spd.PingMs > 50) score -= 15;
            if (spd.JitterMs > 20) score -= 20;
            else if (spd.JitterMs > 10) score -= 10;
            r.Score = Math.Max(0, score);
            r.Grade = r.Score >= 90 ? "A+" : r.Score >= 80 ? "A" : r.Score >= 70 ? "B" : r.Score >= 60 ? "C" : "F";
            r.Status = "Готово";
            return r;
        });
        results.Add(speed);
        OnCheckComplete?.Invoke(speed);

        var bufferbloat = await RunCheck("Bufferbloat", "Производительность", ct, async () =>
        {
            var bb = await BufferbloatService.RunAsync(ct);
            var r = new AuditResult { Name = "Bufferbloat", Category = "Производительность" };
            r.Checks.Add(new AuditCheck { Name = "Idle Ping", Value = $"{bb.IdlePingMs}ms", Passed = bb.IdlePingMs < 30 });
            r.Checks.Add(new AuditCheck { Name = "Loaded Ping", Value = $"{bb.LoadedPingMs}ms", Passed = bb.LoadedPingMs < 100 });
            r.Checks.Add(new AuditCheck { Name = "Увеличение", Value = $"{bb.LoadedPingMs - bb.IdlePingMs}ms", Passed = bb.LoadedPingMs - bb.IdlePingMs < 50 });
            r.Checks.Add(new AuditCheck { Name = "Оценка", Value = bb.Grade, Passed = bb.Grade.StartsWith("A") });
            r.Score = bb.Grade == "A+" ? 100 : bb.Grade == "A" ? 90 : bb.Grade == "B" ? 75 : bb.Grade == "C" ? 60 : bb.Grade == "D" ? 40 : 20;
            r.Grade = bb.Grade;
            r.Status = "Готово";
            return r;
        });
        results.Add(bufferbloat);
        OnCheckComplete?.Invoke(bufferbloat);

        var dns = await RunCheck("DNS", "Безопасность", ct, async () =>
        {
            OnProgress?.Invoke("DNS", "Проверка UDP резолверов...");
            var dnsResults = await DnsAuditService.RunAsync(ct);
            OnProgress?.Invoke("DNS", "Проверка DoH (Cloudflare)...");
            var r = new AuditResult { Name = "DNS", Category = "Безопасность" };
            int encrypted = dnsResults.Count(d => d.IsEncrypted);
            int hijacked = dnsResults.Count(d => d.IsHijacked);
            int fast = dnsResults.Count(d => d.ResponseMs > 0 && d.ResponseMs < 100);
            int timedOut = dnsResults.Count(d => d.ResponseMs < 0);
            r.Checks.Add(new AuditCheck { Name = "Резолверов протестировано", Value = $"{dnsResults.Count}", Passed = true });
            r.Checks.Add(new AuditCheck { Name = "Зашифрованные (DoH)", Value = $"{encrypted}", Passed = encrypted > 0 });
            r.Checks.Add(new AuditCheck { Name = "Перехваченные", Value = $"{hijacked}", Passed = hijacked == 0, Severity = hijacked > 0 ? "critical" : "info" });
            r.Checks.Add(new AuditCheck { Name = "Быстрые (<100ms)", Value = $"{fast}", Passed = fast >= 3 });
            r.Checks.Add(new AuditCheck { Name = "Не отвечает", Value = $"{timedOut}", Passed = timedOut == 0, Severity = timedOut > 3 ? "critical" : "info" });
            foreach (var d in dnsResults.Where(d => d.ResponseMs > 0).OrderBy(d => d.ResponseMs))
                r.Checks.Add(new AuditCheck { Name = d.Resolver, Value = $"{d.ResponseMs}ms{(d.IsEncrypted ? " 🔒" : "")}", Passed = d.ResponseMs < 200 });
            r.Score = Math.Max(0, 100 - (hijacked * 30) - (timedOut * 5) + (encrypted * 5));
            r.Grade = r.Score >= 90 ? "A+" : r.Score >= 80 ? "A" : r.Score >= 70 ? "B" : r.Score >= 60 ? "C" : "F";
            r.Status = "Готово";
            return r;
        });
        results.Add(dns);
        OnCheckComplete?.Invoke(dns);

        var geo = await RunCheck("Гео-блокировка", "Цензура", ct, async () =>
        {
            OnProgress?.Invoke("Гео-блокировка", "Проверка доступности сервисов...");
            var sites = await GeoBlockService.RunAsync(ct);
            var r = new AuditResult { Name = "Гео-блокировка", Category = "Цензура" };
            int blocked = sites.Count(s => s.Blocked);
            var categories = sites.GroupBy(s => s.Category);
            r.Checks.Add(new AuditCheck { Name = "Всего сайтов", Value = $"{sites.Count}", Passed = true });
            r.Checks.Add(new AuditCheck { Name = "Заблокировано", Value = $"{blocked}", Passed = blocked == 0, Severity = blocked > 3 ? "critical" : blocked > 0 ? "warning" : "info" });
            foreach (var cat in categories)
            {
                var catBlocked = cat.Count(s => s.Blocked);
                r.Checks.Add(new AuditCheck { Name = cat.Key, Value = $"{catBlocked}/{cat.Count()}", Passed = catBlocked == 0 });
            }
            foreach (var s in sites.Where(s => s.Blocked))
                r.Checks.Add(new AuditCheck { Name = s.Service, Value = s.Method, Passed = false, Severity = "warning" });
            r.Score = Math.Max(0, 100 - (blocked * 4));
            r.Grade = r.Score >= 90 ? "A+" : r.Score >= 80 ? "A" : r.Score >= 70 ? "B" : r.Score >= 60 ? "C" : "F";
            r.Status = "Готово";
            return r;
        });
        results.Add(geo);
        OnCheckComplete?.Invoke(geo);

        return results;
    }

    private static async Task<AuditResult> RunCheck(string name, string category, CancellationToken ct, Func<Task<AuditResult>> func)
    {
        var messages = new Dictionary<string, string>
        {
            ["IP Info"] = "Определение IP, ISP, страны...",
            ["DPI Детекция"] = "TLS probe к 16 доменам, проверка блокировок...",
            ["Скорость"] = "Замер Download/Ping/Jitter...",
            ["Bufferbloat"] = "Ping idle + нагрузка 8с + анализ...",
            ["DNS"] = "Проверка 7 резолверов + Cloudflare DoH...",
            ["Гео-блокировка"] = "Проверка доступности 20 сервисов..."
        };
        OnProgress?.Invoke(name, messages.TryGetValue(name, out var msg) ? msg : $"Проверяю {name}...");
        try { return await func(); }
        catch (Exception ex)
        {
            return new AuditResult { Name = name, Category = category, Status = "Ошибка", Details = ex.Message, Grade = "F", Score = 0 };
        }
    }
}
