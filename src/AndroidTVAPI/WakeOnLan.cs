using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AndroidTVAPI
{
    /// <summary>
    /// Sends magic WOL packet to wake a device on LAN.
    /// </summary>
    /// <remarks>https://en.wikipedia.org/wiki/Wake-on-LAN</remarks>
    internal static class WakeOnLan
    {
        /// <summary>
        /// Send Wake On LAN to a device on the network.
        /// </summary>
        /// <param name="mac">MAC address in hex format.</param>
        /// <returns>Awaitable <see cref="Task"/>.</returns>
        public static async Task SendAsync(string mac)
        {
            byte[] magicPacket = CreateMagicPacket(mac);
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var networkInterface in networkInterfaces.Where((n) => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();

                foreach (var multicastIP in ipProperties.MulticastAddresses)
                {
                    IPAddress multicastIpAddress = multicastIP.Address;
                    UnicastIPAddressInformation unicastIPAddressInformation = null;

                    if (multicastIpAddress.ToString().StartsWith("ff02::1%", StringComparison.OrdinalIgnoreCase))
                    {
                        unicastIPAddressInformation = 
                            ipProperties.UnicastAddresses
                            .Where((u) => u.Address.AddressFamily == AddressFamily.InterNetworkV6 && !u.Address.IsIPv6LinkLocal)
                            .FirstOrDefault();
                    }
                    else if (multicastIpAddress.ToString().Equals("224.0.0.1", StringComparison.OrdinalIgnoreCase))
                    {
                        unicastIPAddressInformation =
                            ipProperties.UnicastAddresses
                                .Where((u) => u.Address.AddressFamily == AddressFamily.InterNetwork && !ipProperties.GetIPv4Properties().IsAutomaticPrivateAddressingActive)
                                .FirstOrDefault();
                    }

                    if (unicastIPAddressInformation != null)
                    {
                        await SendWakeOnLanAsync(unicastIPAddressInformation.Address, multicastIpAddress, magicPacket);
                    }
                }
            }
        }

        private static byte[] CreateMagicPacket(string mac)
        {
            byte[] macBytes = FromHexString(mac);
            IEnumerable<byte> header = Enumerable.Repeat((byte)0xff, 6); // 6 times 0xFF
            IEnumerable<byte> data = Enumerable.Repeat(macBytes, 16).SelectMany(m => m); // then 16 times mac address
            return header.Concat(data).ToArray();
        }

        private static byte[] FromHexString(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "").Replace(":", "");
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return raw;
        }

        private static async Task SendWakeOnLanAsync(IPAddress localIpAddress, IPAddress multicastIpAddress, byte[] magicPacket)
        {
            using(UdpClient client = new UdpClient(new IPEndPoint(localIpAddress, 0)))
            {
                await client.SendAsync(magicPacket, magicPacket.Length, new IPEndPoint(multicastIpAddress, 9));
            }
        }
    }
}
