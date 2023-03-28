using AndroidTVAPI.API;
using AndroidTVAPI.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AndroidTVAPI
{
    public enum KeyAction : byte
    {
        Down = 1,
        Up = 2,
        Press = 3 // key code channel up/down
    }

    /// <summary>
    /// Android TV client. 
    /// </summary>
    /// <remarks>https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2)</remarks>
    public class AndroidTVClient : AndroidTVClientBase
    {
        private const int REMOTE_PORT = 6466;

        private bool _isConnected = false;
        private AndroidTVConfiguraton _configuration = null;

        private Task _keepAlive;

        /// <summary>
        /// Ctor.
        /// </summary>
        /// <param name="ip">IP address. E.g. 192.168.1.99.</param>
        /// <param name="clientCertificate">Client certificate encoded as PEM.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public AndroidTVClient(string ip, string clientCertificate) : base(ip, REMOTE_PORT, clientCertificate)
        {
            if (clientCertificate == null)
                throw new ArgumentNullException(nameof(clientCertificate));
        }

        private async Task Connect()
        {
            if(_isConnected) 
                return;

            byte[] response;

            // initiate connection
            var networkStream = GetNetworkStream();

            // read the first message
            response = await networkStream.ReadMessage();

            var serverConfig = InitialConfigurationMessage.FromBytes(response);
            _configuration = new AndroidTVConfiguraton()
            {
                ModelName = serverConfig.ModelName,
                VendorName = serverConfig.VendorName,
                Version = serverConfig.Version,
                AppName = serverConfig.AppName,
                AppVersion = serverConfig.AppVersion
            };

            var clientConfig = new InitialConfigurationMessage("Assistant Cloud", "Kodono", "10", "info.kodono.assistant", "1.0.0").ToBytes();
            await networkStream.SendMessage(clientConfig);
            response = await networkStream.ReadMessage();

            // we should get [18, 0] indicating success
            if (response[0] != 18 || response[1] != 0)
                throw new Exception("Unknown error!");

            // send second message
            await networkStream.SendMessage(new byte[] { 18, 3, 8, 238, 4 });

            // server should respond with 3 messages
            for (int i = 0; i < 3; i++)
            {
                response = await networkStream.ReadMessage();
                UpdateConfiguration(_configuration, response);
            }

            _isConnected = true;

            if (_keepAlive == null)
            {
                _keepAlive = Task.Run(async () =>
                {
                    byte[] buffer = new byte[1024];

                    while (_isConnected)
                    {
                        // TODO: add cancelation
                        int read = await networkStream.ReadAsync(buffer, 0, buffer.Length);
                        if(read > 0)
                        {
                            // if we've received a ping
                            if (buffer[0] == 8 && buffer[1] == 66 && buffer[2] == 6)
                            {
                                // send pong
                                await networkStream.SendMessage(new byte[] { 74, 2, 8, 25 });
                            }
                        }
                    }
                });
            }
        }

        private static void UpdateConfiguration(AndroidTVConfiguraton configuration, byte[] message)
        {
            Debug.WriteLine($"Configuration message received: {BitConverter.ToString(message)}");

            switch (message[0])
            {
                case 146:
                    {
                        // indicates the player name and the volume level
                        // TODO
                    }
                    break;

                case 162:
                    {
                        // A2-01-0E-0A-0C-62-0A-63-6F-6D-2E-74-63-6C-2E-74-76
                        // currently opened application
                        int length = message[6];
                        configuration.CurrentApplication = Encoding.ASCII.GetString(message.Skip(7).Take(length).ToArray());
                    }
                    break;

                case 194:
                    {
                        // C2-02-02-08-01
                        // 01 indicates it's on
                        configuration.IsOn = message[4] == 1;
                    }
                    break;

                default:
                    throw new NotSupportedException($"Unknown message {message[0]} received");
            }
        }

        /// <summary>
        /// Get the current TV configuration.
        /// </summary>
        /// <returns><see cref="AndroidTVConfiguraton"/>.</returns>
        /// <exception cref="Exception"></exception>
        public AndroidTVConfiguraton GetConfiguration()
        {
            if (!_isConnected)
                throw new Exception("Not connected!");

            return _configuration;
        }

        /// <summary>
        /// Press key.
        /// </summary>
        /// <param name="code">Key code.</param>
        /// <param name="action">Action - down/up or press.</param>
        /// <returns>Awaitable <see cref="Task"/>.</returns>
        public async Task PressKey(byte code, KeyAction action)
        {
            await Connect();

            // initiate connection
            var networkStream = GetNetworkStream();

            if (action != KeyAction.Press)
            {
               await networkStream.SendMessage(new byte[]
                {
                    82, 4, 8, // the command tag
                    code,
                    16, (byte)action
                });
            }
            else
            {
                await networkStream.SendMessage(new byte[]
                {
                    82, 5, 8, // the command tag
                    code,
                    1,
                    16, (byte)action
                });
            }
        }

        /// <summary>
        /// Start an application using protocol activation.
        /// </summary>
        /// <param name="content">Content.</param>
        /// <returns>Awaitable <see cref="Task"/>.</returns>
        public async Task StartApplication(string content)
        {
            await Connect();

            // initiate connection
            var networkStream = GetNetworkStream();

            List<byte> message = new List<byte>()
                {
                    210, 5, // the command tag
                    0, // dummy size
                    10, // tag
                };

            byte[] contentBytes = Encoding.ASCII.GetBytes(content);
            message.Add((byte)contentBytes.Length);
            message.AddRange(contentBytes);

            // fix size
            message[1] = (byte)(message.Count - 3);

            await networkStream.SendMessage(message.ToArray());
        }

        #region Wake on LAN

        /// <summary>
        /// Turn on the TV using Wake On Lan feature. 
        /// </summary>
        /// <param name="ip">IP address.</param>
        /// <param name="mac">MAC address (optional). When null, ARP will be used to look it up in the LAN.</param>
        /// <returns>Awaitable <see cref="Task"/>.</returns>
        /// <remarks>
        /// The Android TV must support the Wake On LAN functionality. Turn on Settings -> Network and Internet -> Remote Start or similar option depending upon your model.
        /// Tested on TCL C835.
        /// </remarks>
        /// <exception cref="NotSupportedException"></exception>
        public static async Task<string> TurnOnAsync(string ip, string mac = null)
        {
            string resolvedMAC = mac;
            if (string.IsNullOrWhiteSpace(resolvedMAC))
            {
                // try retrieve the MAC address
                try
                {
                    ArpClient arpClient = new ArpClient();
                    resolvedMAC = ArpClient.ResolveMAC(ip);
                }
                catch (Exception ex)
                {
                    Debug.Write(ex.Message);
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedMAC))
            {
                throw new NotSupportedException("Unable to retrieve MAC address, please provide a valid MAC address when creating the client.");
            }

            // send the WOL magic packet to the TV to turn it on
            await WakeOnLan.SendAsync(resolvedMAC);

            return resolvedMAC;
        }

        #endregion // Wake on LAN

        protected override void Dispose(bool disposing)
        {
            _isConnected = false;
            base.Dispose(disposing);
        }
    }
}