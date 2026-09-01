using System;
using System.Collections.Generic;

namespace VPNProbe.Models;

public class AuditResult
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Grade { get; set; } = "—";
    public string Status { get; set; } = "Ожидание";
    public string Details { get; set; } = "";
    public double Score { get; set; }
    public bool IsRunning { get; set; }
    public List<AuditCheck> Checks { get; set; } = new();
}

public class AuditCheck
{
    public string Name { get; set; } = "";
    public bool Passed { get; set; }
    public string Value { get; set; } = "";
    public string Expected { get; set; } = "";
    public string Severity { get; set; } = "info";
}

public class IpInfo
{
    public string Ip { get; set; } = "";
    public string Isp { get; set; } = "";
    public string As { get; set; } = "";
    public string Country { get; set; } = "";
    public string City { get; set; } = "";
    public string Org { get; set; } = "";
    public bool IsVpn { get; set; }
    public bool IsProxy { get; set; }
    public bool IsTor { get; set; }
}

public class SpeedResult
{
    public double DownloadMbps { get; set; }
    public double UploadMbps { get; set; }
    public int PingMs { get; set; }
    public int JitterMs { get; set; }
    public string Server { get; set; } = "";
}

public class BufferbloatResult
{
    public int IdlePingMs { get; set; }
    public int LoadedPingMs { get; set; }
    public int JitterMs { get; set; }
    public string Grade { get; set; } = "";
}

public class DnsResult
{
    public string Resolver { get; set; } = "";
    public int ResponseMs { get; set; }
    public bool IsEncrypted { get; set; }
    public bool IsHijacked { get; set; }
    public bool SupportsDoH { get; set; }
    public bool SupportsDoT { get; set; }
}

public class GeoBlockResult
{
    public string Service { get; set; } = "";
    public string Category { get; set; } = "";
    public bool Blocked { get; set; }
    public string Method { get; set; } = "";
}

public class DpiDetectionResult
{
    public bool TlsBlocking { get; set; }
    public bool Tcp16KBBlocking { get; set; }
    public bool HttpBlocking { get; set; }
    public bool DnsBlocking { get; set; }
    public bool QuicBlocking { get; set; }
    public string Method { get; set; } = "";
    public List<string> BlockedDomains { get; set; } = new();
}
