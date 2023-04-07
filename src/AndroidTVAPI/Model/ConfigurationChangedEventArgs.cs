using System;

namespace AndroidTVAPI.Model
{
    public class ConfigurationChangedEventArgs : EventArgs
    {
        public AndroidTVConfiguraton Configuration { get; private set; }

        public ConfigurationChangedEventArgs(AndroidTVConfiguraton configuration)
        {
            this.Configuration = configuration;
        }
    }
}
