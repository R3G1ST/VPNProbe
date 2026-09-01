using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class PortTlsChecker
{
    public static async Task<CheckResult> CheckAsync(ServerInfo server, CancellationToken ct = default)
    {
        var result = new CheckResult { Server = server };
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(server.Host, server.Port);
            if (await Task.WhenAny(connectTask, Task.Delay(5000, ct)) != connectTask)
            {
                result.Error = "Connection timeout";
                return result;
            }
            await connectTask;
            result.PortOpen = true;

            if (server.Protocol == ProxyProtocol.Trojan ||
                server.Protocol == ProxyProtocol.VmessWs ||
                server.Protocol == ProxyProtocol.VlessWs ||
                server.Protocol == ProxyProtocol.Hysteria2)
            {
                await CheckTlsAsync(client, server, result, ct);
            }
            else if (server.Protocol == ProxyProtocol.VlessReality)
            {
                await CheckRealityAsync(client, server, result, ct);
            }
            else
            {
                result.TlsOk = true;
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        return result;
    }

    private static async Task CheckTlsAsync(TcpClient client, ServerInfo server, CheckResult result, CancellationToken ct)
    {
        try
        {
            var sni = !string.IsNullOrEmpty(server.Sni) ? server.Sni : server.Host;
            using var ssl = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            };
            await ssl.AuthenticateAsClientAsync(opts, ct);

            var cert = ssl.RemoteCertificate;
            if (cert != null)
            {
                result.TlsOk = true;
                var x509 = new X509Certificate2(cert);
                result.TlsExpiry = x509.NotAfter.ToString("yyyy-MM-dd");
            }
        }
        catch { result.TlsOk = false; }
    }

    private static async Task CheckRealityAsync(TcpClient client, ServerInfo server, CheckResult result, CancellationToken ct)
    {
        try
        {
            var sni = !string.IsNullOrEmpty(server.Sni) ? server.Sni : "www.google.com";
            using var ssl = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
            };
            await ssl.AuthenticateAsClientAsync(opts, ct);
            result.TlsOk = true;
            var cert = ssl.RemoteCertificate;
            if (cert != null)
            {
                var x509 = new X509Certificate2(cert);
                result.TlsExpiry = x509.NotAfter.ToString("yyyy-MM-dd");
            }
        }
        catch { result.TlsOk = false; }
    }
}
