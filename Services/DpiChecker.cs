using System;
using System.Net;
using System.Net.Sockets;
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

            if (server.Protocol == ProxyProtocol.VlessReality)
            {
                result.DpiBlocked = !await TestRealityHandshake(stream, server, ct);
            }
            else if (server.Protocol == ProxyProtocol.Trojan)
            {
                result.DpiBlocked = !await TestTrojanHandshake(stream, server, ct);
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
            var clientHello = GenerateRealityClientHello(server);
            await stream.WriteAsync(clientHello, ct);
            await Task.Delay(1000, ct);
            return stream.DataAvailable;
        }
        catch { return false; }
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

    private static byte[] GenerateRealityClientHello(ServerInfo server)
    {
        return Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {server.Sni}\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
    }
}
