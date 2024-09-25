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
    }
}
