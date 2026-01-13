namespace Keyfactor.Extensions.CAPlugin.DigicertMpki
{
    public class DigicertMpkiConfig
    {

		public DigicertMpkiConfig()
		{

		}
		public string ApiKey { get; set; }
		public string DigiCertSymUrl { get; set; }
		public string ClientCertLocation {  get; set; }
        public string ClientCertPassword { get; set; }
        public string EndPointAddress { get; set; }
        public string DnsConstName { get; set; }
        public string IpConstName { get; set; }
        public string EmailConstName { get; set; }
        public string UpnConstName { get; set; }
        public int OuStartPoint { get; set; }
        /// <summary>
        /// Optional directory path for enrollment templates.
        /// Supports absolute paths (e.g., /templates or C:\templates) for container volume mounts.
        /// If not specified, defaults to the executing assembly directory.
        /// </summary>
        public string TemplateDirectory { get; set; }
        /// <summary>
        /// Optional JSON string containing an array of enrollment templates.
        /// When provided, templates are loaded from this config value instead of files.
        /// This is ideal for container deployments where file mounts are not desired.
        /// Format: [{"profile":{"id":"..."},"csr":"CSR|RAW",...}, {...}]
        /// </summary>
        public string TemplatesJson { get; set; }
    }
}
