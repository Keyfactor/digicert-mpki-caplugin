namespace Keyfactor.Extensions.CAPlugin.DigicertMpki
{
	public class Constants
	{
        public static string DigiCertSymUrl = "DigiCertSymUrl";
        public static string DigiCertSymApiKey = "ApiKey";
        public static int DefaultPageSize = 100;
        public static string EndpointAddress = "EndpointAddress";
        public static string ClientCertLocation = "ClientCertLocation";
        public static string ClientCertPassword = "ClientCertPassword";
        public static string DnsConstName = "DnsConstName";
        public static string IpConstName = "IpConstName";
        public static string EmailConstName = "EmailConstName";
        public static string UpnConstName = "UpnConstName";
        public static string OuStartPoint = "OuStartPoint";
        public static string TemplateDirectory = "TemplateDirectory";
        public static string TemplatesJson = "TemplatesJson";

        // Environment variable names for container deployment
        public static string EnvApiKey = "DIGICERT_API_KEY";
        public static string EnvClientCertPassword = "DIGICERT_CLIENT_CERT_PASSWORD";
        public static string EnvClientCertBase64 = "DIGICERT_CLIENT_CERT_BASE64";
    }
}
