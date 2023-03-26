using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
        private class InitialConfigurationMessage
        {
            public InitialConfigurationMessage(string modelName, string vendorName, string version, string appName, string appVersion)
                : this(new byte[] { 8, 238, 4, 18 }, modelName, vendorName, version, appName, appVersion)
            { }

            private InitialConfigurationMessage(byte[] unknown, string modelName, string vendorName, string version, string appName, string appVersion)
            {
                Unknown = unknown;
                ModelName = modelName;
                VendorName = vendorName;
                Version = version;
                AppName = appName;
                AppVersion = appVersion;
            }

            public byte[] Unknown { get; }
            public string ModelName { get; }
            public string VendorName { get; }
            public string Version { get; }
            public string AppName { get; }
            public string AppVersion { get; }

            public static InitialConfigurationMessage FromBytes(byte[] bytes)
            {
                using (var ms = new MemoryStream(bytes))
                {
                    using (BinaryReader br = new BinaryReader(ms))
                    {
                        if (br.ReadByte() != 10) // tag
                            throw new Exception("Invalid initial message");

                        int sizeOfTheWholeMessage = br.ReadByte();
                        byte[] unknown = br.ReadBytes(4); // 8, 255, 4, 18 or 8, 239, 4, 18: ??
                        int sizeOfSubmessage = br.ReadByte();

                        if (br.ReadByte() != 10) // tag
                            throw new Exception("Invalid initial message");

                        int sizeOfModelName = br.ReadByte();
                        string modelName = Encoding.ASCII.GetString(br.ReadBytes(sizeOfModelName));

                        if (br.ReadByte() != 18) // tag
                            throw new Exception("Invalid initial message");

                        int sizeOfVendorName = br.ReadByte();
                        string vendorName = Encoding.ASCII.GetString(br.ReadBytes(sizeOfVendorName));

                        byte[] unknown2 = br.ReadBytes(3); // 24, 1, 34 ??

                        int sizeOfVersion = br.ReadByte();
                        string version = Encoding.ASCII.GetString(br.ReadBytes(sizeOfVersion));

                        if (br.ReadByte() != 42) // tag
                            throw new Exception("Invalid initial message");

                        int sizeOfPackageName = br.ReadByte();
                        string appName = Encoding.ASCII.GetString(br.ReadBytes(sizeOfPackageName));

                        int sizeOfAppVersion = br.ReadByte();
                        string appVersion = Encoding.ASCII.GetString(br.ReadBytes(sizeOfAppVersion));

                        return new InitialConfigurationMessage(unknown, modelName, vendorName, version, appName, appVersion);
                    }
                }
            }

            public byte[] ToBytes()
            {
                using (var ms = new MemoryStream())
                {
                    using (BinaryWriter bw = new BinaryWriter(ms))
                    {
                        bw.Write((byte)10); // tag
                        bw.Write((byte)0); // dummy size
                        bw.Write(Unknown); // 8, 238, 4, 18 ??
                        bw.Write((byte)0); // dummy submessage size
                        bw.Write((byte)10); // tag

                        byte[] modelName = Encoding.ASCII.GetBytes(ModelName);
                        bw.Write((byte)modelName.Length);
                        bw.Write(modelName);

                        bw.Write((byte)18); // tag

                        byte[] vendorName = Encoding.ASCII.GetBytes(VendorName);
                        bw.Write((byte)vendorName.Length);
                        bw.Write(vendorName);

                        bw.Write(new byte[] { 24, 1, 34 });

                        byte[] version = Encoding.ASCII.GetBytes(Version);
                        bw.Write((byte)version.Length);
                        bw.Write(version);

                        bw.Write((byte)42); // tag

                        byte[] appName = Encoding.ASCII.GetBytes(AppName);
                        bw.Write((byte)appName.Length);
                        bw.Write(appName);

                        byte[] appVersion = Encoding.ASCII.GetBytes(AppVersion);
                        bw.Write((byte)appVersion.Length);
                        bw.Write(appVersion);
                    }

                    byte[] message = ms.ToArray();

                    // patch the dummy sizes
                    message[1] = (byte)(message.Length - 1);
                    message[6] = (byte)(message.Length - 7);

                    return message;
                }
            }
        }

        private const int REMOTE_PORT = 6466;

        private string _mac;

        private bool _isConnected = false;
        private InitialConfigurationMessage _serverConfig;

        private Task _keepAlive;

        /// <summary>
        /// Ctor.
        /// </summary>
        /// <param name="ip">IP address. E.g. 192.168.1.99.</param>
        /// <param name="clientCertificate">Client certificate encoded as PEM.</param>
        /// <param name="mac"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public AndroidTVClient(string ip, string clientCertificate, string mac = null) : base(ip, REMOTE_PORT, clientCertificate)
        {
            if (clientCertificate == null)
                throw new ArgumentNullException(nameof(clientCertificate));

            this._mac = mac; // when null, we'll try to use ARP to resolve it
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
            _serverConfig = InitialConfigurationMessage.FromBytes(response);

            var clientConfig = new InitialConfigurationMessage("Assistant Cloud", "Kodono", "10", "info.kodono.assistant", "1.0.0").ToBytes();
            await networkStream.SendMessage(clientConfig);
            response = await networkStream.ReadMessage();

            if (response[7] != 18 || response[8] != 0)
                throw new Exception("Unknown error!");

            // send second message
            await networkStream.SendMessage(new byte[]
            {
                18, 3, 8, 238, 4
            });

            // server should respond with 3 messages
            byte[] response1 = await networkStream.ReadMessage();
            Debug.WriteLine($"Response 1: {BitConverter.ToString(response1)}");

            byte[] response2 = await networkStream.ReadMessage();
            Debug.WriteLine($"Response 2: {BitConverter.ToString(response2)}");

            byte[] response3 = await networkStream.ReadMessage();
            Debug.WriteLine($"Response 3: {BitConverter.ToString(response3)}");

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
        /// <returns>Awaitable <see cref="Task"/>.</returns>
        /// <remarks>
        /// The Android TV must support the Wake On LAN functionality. Turn on Settings -> Network and Internet -> Remote Start or similar option depending upon your model.
        /// Tested on TCL C835.
        /// </remarks>
        /// <exception cref="NotSupportedException"></exception>
        public async Task TurnOnAsync()
        {
            this._mac = await TurnOnAsync(GetIP(), this._mac);
        }

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