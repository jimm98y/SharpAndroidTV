using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace AndroidTVAPI
{
    /// <summary>
    /// Simple ARP client that resolves IP addresses to MAC addresses using system commands.
    /// </summary>
    internal class ArpClient
    {
        /// <summary>
        /// Use ARP to resolve the MAC address from the given IP address.
        /// </summary>
        /// <param name="ip">IP address.</param>
        /// <returns>MAC address.</returns>
        public static string ResolveMAC(string ip)
        {
            // first we must ping the target so that the computer running this code caches the ARP response
            // Windows: ping -4 ip -N 1
            // macOS:   ping ip -c 1
            // Linux:   ping ip -c 1
            string command = null;
            string parameters = null;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                command = "ping";
                parameters = $"-4 {ip} -n 1";
            }
            else
            {
                command = "ping";
                parameters = $"{ip} -c 1";
            }
            
            ExecuteCommand(command, parameters);

            // then we can use the arp command to list the MAC addresses
            // Windows: arp -a 192.168.1.99
            // macOS: arp 192.168.1.99
            // Linux: arp 192.168.1.99
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                command = "arp";
                parameters = $"-a {ip}";
            }
            else
            {
                command = "arp";
                parameters = $"{ip}";
            }

            string arpOutput = ExecuteCommand(command, parameters);

            // and parse the output - 3 platforms, 3 different outputs
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var lines = arpOutput.Split(new char[] { '\r', '\n' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                var parts = lines[2].Split(new char[] { ' ', '\t' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                return parts[1];
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var lines = arpOutput.Split(new char[] { '\r', '\n' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                var parts = lines[0].Split(new char[] { ' ', '\t' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                return parts[3];
            }
            else
            {
                // fallback for Linux
                var lines = arpOutput.Split(new char[] { '\r', '\n' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                var parts = lines[1].Split(new char[] { ' ', '\t' }).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
                return parts[2];
            }
        }

        private static string ExecuteCommand(string command, string parameters)
        {
            Process process = new Process();

            process.StartInfo.FileName = command;
            process.StartInfo.Arguments = parameters; 
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;

            process.Start();
            process.WaitForExit();

            string output = process.StandardOutput.ReadToEnd();
            if(!string.IsNullOrEmpty(output))
                return output;

            string err = process.StandardError.ReadToEnd();
            if (!string.IsNullOrEmpty(err))
                return err;

            return null;
        }
    }
}
