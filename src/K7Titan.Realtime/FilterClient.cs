using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace K7Titan.Realtime;

public static class FilterClient
{
    private const uint PdfMaximum = 0x1;
    private const int HResultAlreadyConnected = unchecked((int)0x80070037);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILTER_MESSAGE_HEADER
    {
        public uint ReplyLength;
        public ulong MessageId;
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort dwSizeOfContext,
        IntPtr lpSecurityAttributes,
        out IntPtr hPort);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterGetMessage(
        IntPtr hPort,
        IntPtr lpMessageBuffer,
        uint dwMessageBufferSize,
        IntPtr lpOverlapped);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterClose(IntPtr hPort);

    public static async Task RunAsync(string portName, Func<string, CancellationToken, Task<bool>> onPath, CancellationToken ct)
    {
        var hr = FilterConnectCommunicationPort(portName, 0, IntPtr.Zero, 0, IntPtr.Zero, out var port);
        if (hr != 0 && hr != HResultAlreadyConnected)
        {
            throw new InvalidOperationException($"FilterConnectCommunicationPort failed: 0x{hr:X8}");
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Yield();
                const int headerSize = 16;
                const int nameSize = 260 * sizeof(char);
                var buffer = Marshal.AllocHGlobal(headerSize + nameSize);
                try
                {
                    var r = FilterGetMessage(port, buffer, (uint)(headerSize + nameSize), IntPtr.Zero);
                    if (r == 0)
                    {
                        var path = Marshal.PtrToStringUni(buffer + headerSize) ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            await onPath(path, ct);
                        }
                    }
                    else
                    {
                        await Task.Delay(250, ct);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        finally
        {
            FilterClose(port);
        }
    }
}
