namespace Keyfactor.Extensions.CAPlugin.DigicertMpki
{
    public class DigicertMpkiConfig
    {

		public DigicertMpkiConfig()
		{

		}
		public string ApiKey { get; set; }
		public string BaseUrl { get; set; }
		public string ClientCertificateLocation {  get; set; }
        public string ClientCertificatePassword { get; set; }
        public string EndPointAddress { get; set; }
    }
}
