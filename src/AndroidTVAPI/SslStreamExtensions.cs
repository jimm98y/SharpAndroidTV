using Org.BouncyCastle.Crypto.Paddings;
using System;
using System.IO;
using System.Threading.Tasks;

namespace AndroidTVAPI
{
    internal static class SslStreamExtensions
    {
        public static async Task SendMessage(this Stream networkStream, byte[] messageBytes)
        {
            int length = messageBytes.Length;
            byte[] lengthBytes = new byte[] { (byte)length };
            await networkStream.WriteAsync(lengthBytes, 0, lengthBytes.Length);
            await networkStream.WriteAsync(messageBytes, 0, length);
            await networkStream.FlushAsync();
        }

        public static async Task<byte[]> ReadBytes(this Stream networkStream, int count)
        {
            byte[] bytes = new byte[count];
            int readCount = 0;

            while (readCount < count)
            {
                int left = count - readCount;
                int r = await networkStream.ReadAsync(bytes, readCount, left);

                if (r == 0)
                {
                    throw new Exception("Lost Connection during read");
                }

                readCount += r;
            }

            return bytes;
        }

        public static async Task<byte[]> ReadMessage(this Stream networkStream)
        {
            byte[] len = await ReadBytes(networkStream, 1);
            int length = len[0];
            byte[] messageBytes = await ReadBytes(networkStream, length);
            return messageBytes;
        }
    }
}
