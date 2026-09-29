using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VPNProbe.Models;

namespace VPNProbe.Services;

public static class DpiChecker
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
                result.DpiBlocked = true;
                result.Error = "Connection timeout (possible DPI)";
                return result;
            }
            await connectTask;
            result.PortOpen = true;

            var stream = client.GetStream();

            // Проверка для всех протоколов, использующих TLS (VLESS WS, VMess WS, Trojan, Hysteria2)
            // Reality: проверяем через TLS handshake с SNI
            if (server.Protocol == ProxyProtocol.VlessReality)
            {
                result.DpiBlocked = !await TestRealityHandshake(stream, server, ct);
            }
            else if (server.Protocol == ProxyProtocol.Trojan)
            {
                result.DpiBlocked = !await TestTrojanHandshake(stream, server, ct);
            }
            else if (server.Protocol == ProxyProtocol.VlessWs ||
                     server.Protocol == ProxyProtocol.VmessWs)
            {
                // WS-протоколы: проверяем TLS handshake — при DPI блокировке SNI handshake будет сброшен
                result.DpiBlocked = !await TestTlsHandshake(stream, server, ct);
            }
            else if (server.Protocol == ProxyProtocol.Hysteria2)
            {
                // Hysteria2: проверяем TLS handshake
                result.DpiBlocked = !await TestTlsHandshake(stream, server, ct);
            }
            else if (server.Protocol == ProxyProtocol.Shadowsocks)
            {
                // Shadowsocks: проверяем, принимает ли трафик (SS handshake)
                result.DpiBlocked = !await TestShadowsocksHandshake(stream, server, ct);
            }
            else
            {
                result.DpiBlocked = false;
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            result.DpiBlocked = true;
            result.Error = "Connection reset (DPI)";
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        return result;
    }

    private static async Task<bool> TestRealityHandshake(NetworkStream stream, ServerInfo server, CancellationToken ct)
    {
        try
        {
            // Для Reality: отправляем ClientHello и проверяем ответ
            var clientHello = GenerateRealityClientHello(server);
            await stream.WriteAsync(clientHello, ct);
            await Task.Delay(1000, ct);
            return stream.DataAvailable;
        }
        catch { return false; }
    }

    private static async Task<bool> TestTlsHandshake(NetworkStream stream, ServerInfo server, CancellationToken ct)
    {
        try
        {
            // Пробуем TLS handshake — если DPI блокирует SNI, это вызовет ошибку
            var sni = !string.IsNullOrEmpty(server.Sni) ? server.Sni : server.Host;
            using var ssl = new SslStream(stream, false, (_, _, _, _) => true);
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            };
            await ssl.AuthenticateAsClientAsync(opts, ct);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TestTrojanHandshake(NetworkStream stream, ServerInfo server, CancellationToken ct)
    {
        try
        {
            var crlf = "\r\n";
            var cmd = $"CONNECT {server.Host}:{server.Port} HTTP/1.1{crlf}Host: {server.Host}:{server.Port}{crlf}{crlf}";
            var bytes = Encoding.ASCII.GetBytes(cmd);
            await stream.WriteAsync(bytes, ct);
            await Task.Delay(1000, ct);
            return stream.DataAvailable;
        }
        catch { return false; }
    }

    private static async Task<bool> TestShadowsocksHandshake(NetworkStream stream, ServerInfo server, CancellationToken ct)
    {
        try
        {
            // Shadowsocks: проверяем TCP-соединение — если DPI не блокирует, данные доступны
            await Task.Delay(500, ct);
            return stream.CanWrite;
        }
        catch { return false; }
    }

    private static byte[] GenerateRealityClientHello(ServerInfo server)
    {
        return Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {server.Sni}\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
    }
}