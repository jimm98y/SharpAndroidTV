using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AndroidTVAPI
{
    internal static class SslStreamExtensions
    {
        public static async Task SendMessage(this Stream networkStream, byte[] messageBytes, CancellationToken token)
        {
            int length = messageBytes.Length;
            byte[] lengthBytes = new byte[] { (byte)length };
            await networkStream.WriteAsync(lengthBytes, 0, lengthBytes.Length, token);
            await networkStream.WriteAsync(messageBytes, 0, length, token);
            await networkStream.FlushAsync(token);
        }

        public static async Task<byte[]> ReadBytes(this Stream networkStream, int count, CancellationToken token)
        {
            byte[] bytes = new byte[count];
            int readCount = 0;

            while (readCount < count)
            {
                int left = count - readCount;
                int r = await networkStream.ReadAsync(bytes, readCount, left, token);

                if (r == 0)
                {
                    throw new Exception("Lost Connection during read");
                }

                readCount += r;
            }

            return bytes;
        }

        public static async Task<byte[]> ReadMessage(this Stream networkStream, CancellationToken token)
        {
            byte[] len = await ReadBytes(networkStream, 1, token);
            int length = len[0];
            byte[] messageBytes = await ReadBytes(networkStream, length, token);
            return messageBytes;
        }
    }
}
