namespace AndroidTVAPI.Model
{
    /// <summary>
    /// Current Android TV configuration.
    /// </summary>
    public class AndroidTVConfiguraton
    {
        /// <summary>
        /// Model name.
        /// </summary>
        public string ModelName { get; internal set; }

        /// <summary>
        /// Vendor name.
        /// </summary>
        public string VendorName { get; internal set; }

        /// <summary>
        /// Version.
        /// </summary>
        public string Version { get; internal set; }

        /// <summary>
        /// App name.
        /// </summary>
        public string AppName { get; internal set; }

        /// <summary>
        /// App version.
        /// </summary>
        public string AppVersion { get; internal set; }

        /// <summary>
        /// Is the TV on?
        /// </summary>
        public bool IsOn { get; internal set; }

        /// <summary>
        /// Currently opened application.
        /// </summary>
        public string CurrentApplication { get; internal set; }

        /// <summary>
        /// Current volume.
        /// </summary>
        public int CurrentVolume { get; internal set; }
    }
}
