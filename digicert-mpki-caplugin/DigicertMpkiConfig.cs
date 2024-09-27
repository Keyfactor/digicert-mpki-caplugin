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
    }
}
