using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

namespace AndroidTVAPI
{
    /// <summary>
    /// Android TV pairing client. 
    /// </summary>
    /// <remarks>Pairing algorithm described here: https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2)</remarks>
    public class AndroidTVPairingClient : AndroidTVClientBase
    {
        private const int PAIRING_PORT = 6467;

        private string _clientCertificatePem = null;
        private X509Certificate2 _serverCertificate;
        private bool _isPairingInProgress = false;

        /// <summary>
        /// Ctor.
        /// </summary>
        /// <param name="ip">IP address. E.g. 192.168.1.99.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public AndroidTVPairingClient(string ip, string clientCertificate = null) : base(ip, PAIRING_PORT)
        { 
            if(clientCertificate != null)
            {
                this._clientCertificatePem = clientCertificate;
            }
        }

        /// <summary>
        /// Initiates pairing with the TV.
        /// </summary>
        public async Task InitiatePairing()
        {
            if (this._serverCertificate == null)
            {
                this._serverCertificate = GetPublicCertificate(GetIP(), PAIRING_PORT);
            }

            if (this.ClientCertificate == null)
            {
                this._clientCertificatePem = CertificateUtils.GenerateCertificate(
                    "atvremote",
                    "US",
                    "California",
                    "Mountain View",
                    "Google Inc.",
                    "Android",
                    "example@google.com",
                    DateTime.UtcNow.Date,
                    DateTime.UtcNow.Date.AddYears(10));
                SetClientCertificate(this._clientCertificatePem);
            }

            var networkStream = GetNetworkStream();

            byte[] response;

            await SendPairingMessage(networkStream);
            response = await networkStream.ReadMessage();
            VerifyResult(response);

            await SendOptionMessage(networkStream);
            response = await networkStream.ReadMessage();
            VerifyResult(response);

            // TV should go to the pairing mode now
            await SendConfigurationMessage(networkStream);
            response = await networkStream.ReadMessage();
            VerifyResult(response);

            this._isPairingInProgress = true;
        }

        /// <summary>
        /// Complete pairing process.
        /// </summary>
        /// <param name="code">Code shown on the TV.</param>
        /// <returns>Client certificate paired with the TV encoded as PEM.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public async Task<string> CompletePairing(string code)
        {
            if(!this._isPairingInProgress)
                throw new InvalidOperationException($"You must first start pairing by calling {nameof(InitiatePairing)}!");

            if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
                throw new ArgumentException("Invalid code! Expected 6 letters.");
            
            var networkStream = GetNetworkStream();
            await SendSecretMessage(networkStream, code, this.ClientCertificate, this._serverCertificate);
            byte[] response = await networkStream.ReadMessage();
            VerifyResult(response);

            this._isPairingInProgress = false;

            return this._clientCertificatePem;
        }

        private static byte[] GetAlphaValue(string code, X509Certificate2 clientCertificate, X509Certificate2 serverCertificate)
        {
            // nonce are the last 4 characters of the code displayed on the TV
            byte[] nonce = StringToByteArray(code.Substring(2)).ToArray();

            var client = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(clientCertificate);
            var server = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(serverCertificate);

            var publicKey = client.GetPublicKey();
            var publicKey2 = server.GetPublicKey();

            var rSAPublicKey = (RsaKeyParameters)publicKey;
            var rSAPublicKey2 = (RsaKeyParameters)publicKey2;

            var instance = new Sha256Digest();
           
            byte[] clientModulus = RemoveLeadingZeroBytes(rSAPublicKey.Modulus.Abs().ToByteArray());
            byte[] clientExponent = RemoveLeadingZeroBytes(rSAPublicKey.Exponent.Abs().ToByteArray());
            byte[] serverModulus = RemoveLeadingZeroBytes(rSAPublicKey2.Modulus.Abs().ToByteArray());
            byte[] serverExponent = RemoveLeadingZeroBytes(rSAPublicKey2.Exponent.Abs().ToByteArray());

            Debug.WriteLine("Hash inputs: ");
            Debug.WriteLine("client modulus: " + BitConverter.ToString(clientModulus));
            Debug.WriteLine("client exponent: " + BitConverter.ToString(clientExponent));
            Debug.WriteLine("server modulus: " + BitConverter.ToString(serverModulus));
            Debug.WriteLine("server exponent: " + BitConverter.ToString(serverExponent));
            Debug.WriteLine("nonce: " + BitConverter.ToString(nonce));

            instance.BlockUpdate(clientModulus, 0, clientModulus.Length);
            instance.BlockUpdate(clientExponent, 0, clientExponent.Length);
            instance.BlockUpdate(serverModulus, 0, serverModulus.Length);
            instance.BlockUpdate(serverExponent, 0, serverExponent.Length);
            instance.BlockUpdate(nonce, 0, nonce.Length);

            byte[] hash = new byte[instance.GetDigestSize()];
            instance.DoFinal(hash, 0);
                
            Debug.WriteLine("hash: " + BitConverter.ToString(hash));

            return hash;
        }

        private static async Task SendSecretMessage(Stream networkStream, string code, X509Certificate2 clientCertificate, X509Certificate2 serverCertificate)
        {
            List<byte> message = new List<byte>()
            {
                8, 2,       // protocol version 2
                16, 200, 1, // status code OK
                194, 2, 34, 10, // ??
                32,         // size of the encoded secret
            };

            message.AddRange(GetAlphaValue(code, clientCertificate, serverCertificate));

            if (message.Count != 42)
                throw new InvalidOperationException("Invalid pairing message!");

            await networkStream.SendMessage(message.ToArray());
        }

        private static async Task SendConfigurationMessage(Stream networkStream)
        {
            List<byte> message = new List<byte>()
            {
                8, 2,       // protocol version 2
                16, 200, 1, // status code OK
                242,        // message tag
                1,          // ??
                8,          // encoding tag?
                10,         // ??
                4,          // size??
                8,          // type tag
                3,          // 0 for ENCODING_TYPE_UNKNOWN, 1 for ENCODING_TYPE_ALPHANUMERIC, 2 for ENCODING_TYPE_NUMERIC, 3 for ENCODING_TYPE_HEXADECIMAL, 4 for ENCODING_TYPE_QRCODE
                16,         // size tag?
                6,          // symbol length?
                16,         // preferred role tag?
                1           // 1 for ROLE_TYPE_INPUT
            };

            await networkStream.SendMessage(message.ToArray());
        }

        private static async Task SendOptionMessage(Stream networkStream)
        {
            List<byte> message = new List<byte>()
            {
                8, 2,       // protocol version 2
                16, 200, 1, // status code OK
                162,        // message tag
                1,          // ??
                8,          // encoding output?
                10,         // ??
                4,
                8,
                3,          // 0 for ENCODING_TYPE_UNKNOWN, 1 for ENCODING_TYPE_ALPHANUMERIC, 2 for ENCODING_TYPE_NUMERIC, 3 for ENCODING_TYPE_HEXADECIMAL, 4 for ENCODING_TYPE_QRCODE
                16,         // size tag?
                6,          // symbol length?
                24,         // preferred role tag?
                1           // 1 for ROLE_TYPE_INPUT
            };

            await networkStream.SendMessage(message.ToArray());
        }

        private static async Task SendPairingMessage(Stream networkStream)
        {
            List<byte> message = new List<byte>()
            {
                8, 2,       // protocol version 2
                16, 200, 1, // status code OK
                82,         // message tag
                43,         // length of the message (changed later)
                10,         // service name tag
            };

            //21,   105,110,102,111,46,107,111,100,111,110,111,46,97,115,115,105,115,116,97,110,116, // 21 size, service name: info.kodono.assistant
            byte[] serviceName = Encoding.ASCII.GetBytes("info.kodono.assistant");
            message.Add((byte)serviceName.Length);
            message.AddRange(serviceName);

            message.Add(18); // tag device name

            //13,   105, 110, 116, 101, 114, 102, 97, 99, 101, 32, 119, 101, 98, // 13 size, client name: interface web
            byte[] clientName = Encoding.ASCII.GetBytes("interface web");
            message.Add((byte)clientName.Length);
            message.AddRange(clientName);

            // length of the message minus version length
            message[6] = (byte)(message.Count - 2);

            await networkStream.SendMessage(message.ToArray());
        }

        private static void VerifyResult(byte[] response)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));

            if (response[0] != 8 || response[1] != 2)
                throw new Exception("Invalid protocol version!");

            if (response[2] != 16 || response[3] != 200 || response[4] != 1)
            {
                if (response[4] == 3)
                {
                    if (response[3] == 144)
                        throw new Exception("ERROR");
                    else if (response[3] == 145)
                        throw new Exception("BAD CONFIGURATION");
                    else
                        throw new Exception("UNKNOWN ERROR");
                }
                else
                {
                    throw new Exception("UNKNOWN");
                }
            }
        }

        private static X509Certificate2 GetPublicCertificate(string host, int port)
        {
            X509Certificate2 cert = null;

            using (TcpClient client = new TcpClient())
            {
                client.Connect(host, port);

                SslStream ssl = new SslStream(
                    client.GetStream(),
                    false,
                    new RemoteCertificateValidationCallback((s, c, ch, err) => { return true; }), null);

                try
                {
                    ssl.AuthenticateAsClient(host);
                }
                catch (AuthenticationException e)
                {
                    Debug.WriteLine(e.Message);
                    ssl.Close();
                    client.Close();
                    return cert;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    ssl.Close();
                    client.Close();
                    return cert;
                }

                cert = new X509Certificate2(ssl.RemoteCertificate);
                ssl.Close();
                client.Close();

                return cert;
            }
        }

        private static byte[] RemoveLeadingZeroBytes(byte[] array)
        {
            int skip = 0;
            for (int i = 0; i < array.Length; i++)
            {
                if (array[i] != 0)
                {
                    skip = i; 
                    break;
                }
            }

            return array.Skip(skip).ToArray();
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
