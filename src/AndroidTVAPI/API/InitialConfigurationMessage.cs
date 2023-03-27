using System;
using System.IO;
using System.Text;

namespace AndroidTVAPI.API
{
    internal class InitialConfigurationMessage
    {
        public byte[] Unknown { get; }
        public string ModelName { get; }
        public string VendorName { get; }
        public string Version { get; }
        public string AppName { get; }
        public string AppVersion { get; }

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
}
