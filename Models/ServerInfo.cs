using System;
using System.Collections.Generic;
using System.Net;

namespace VPNProbe.Models;

public enum ProxyProtocol
{
    Unknown,
    VlessReality,
    VlessWs,
    Trojan,
    Hysteria2,
    VmessWs,
    Shadowsocks,
    HttpProxy,
    Socks5,
    Tuic
}

public class ServerInfo
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public ProxyProtocol Protocol { get; set; }
    public string RawUri { get; set; } = "";
    public string Password { get; set; } = "";
    public string Uuid { get; set; } = "";
    public string Sni { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string Path { get; set; } = "";
    public string HostHeader { get; set; } = "";

    public string DisplayName => $"{ProtocolName} | {Name} | {Host}:{Port}";
    public string ProtocolName => Protocol switch
    {
        ProxyProtocol.VlessReality => "VLESS Reality",
        ProxyProtocol.VlessWs => "VLESS WS",
        ProxyProtocol.Trojan => "Trojan",
        ProxyProtocol.Hysteria2 => "Hysteria2",
        ProxyProtocol.VmessWs => "VMess WS",
        ProxyProtocol.Shadowsocks => "Shadowsocks",
        ProxyProtocol.HttpProxy => "HTTP",
        ProxyProtocol.Socks5 => "SOCKS5",
        ProxyProtocol.Tuic => "TUIC",
        _ => "Unknown"
    };
}

public class CheckResult
{
    public ServerInfo Server { get; set; } = null!;
    public int PingMs { get; set; } = -1;
    public bool PingOk { get; set; }
    public bool PortOpen { get; set; }
    public bool TlsOk { get; set; }
    public string TlsExpiry { get; set; } = "";
    public bool ProxyOk { get; set; }
    public string ProxyIp { get; set; } = "";
    public bool DpiBlocked { get; set; }
    public string Error { get; set; } = "";
    public string Status => GetStatus();

    private string GetStatus()
    {
        if (!PingOk && !PortOpen) return "Offline";
        if (!PortOpen) return "Port blocked";
        if (!TlsOk) return "TLS fail";
        if (ProxyOk) return "OK";
        if (DpiBlocked) return "DPI blocked";
        return "Connect fail";
    }
}

public class SubscriptionData
{
    public string Url { get; set; } = "";
    public List<ServerInfo> Servers { get; set; } = new();
    public string Error { get; set; } = "";
    public bool IsEmpty => Servers.Count == 0;
}
