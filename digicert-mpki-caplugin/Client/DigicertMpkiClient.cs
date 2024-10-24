using System.Text;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;
using Keyfactor.Logging;
using System.Net.Http;
using System;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.DigicertMpki.Client.Models;
using System.IO;
using System.Net.Http.Headers;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.DigicertMpki;
using System.ServiceModel;
using DigicertMpkiSoap;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using Keyfactor.Extensions.CAPlugin.DigicertMpki.Models;

namespace Keyfactor.Extensions.CAPlugin.DigicertMpki.Client
{
    public class DigiCertSymClient
    {

        private readonly ILogger _logger;
        private Uri BaseUrl { get; }
        private HttpClient RestClient { get; }
        private string ApiKey { get; }
        private string EndPointAddress { get; }
        private string ClientCertificateLocation { get; }
        private string ClientCertificatePassword { get; }

        public DigiCertSymClient(DigicertMpkiConfig config, ILogger logger)
        {
            try
            {
                _logger = logger;
                BaseUrl =new Uri(config.DigiCertSymUrl);
                ApiKey=config.ApiKey;
                ClientCertificateLocation=config.ClientCertLocation;
                ClientCertificatePassword =config.ClientCertPassword;
                EndPointAddress = config.EndPointAddress;
                RestClient = ConfigureRestClient();
            }
            catch (Exception e)
            {
                _logger.LogError($"DigiCertSymClient Constructor Error Occurred: {e.Message}");
                throw;
            }
        }

        public async Task<EnrollmentResponse> SubmitEnrollmentAsync(
            EnrollmentRequest enrollmentRequest)
        {
            try
            {
                using (var resp = await RestClient.PostAsync("/mpki/api/v1/certificate", new StringContent(
                    JsonConvert.SerializeObject(enrollmentRequest), Encoding.ASCII, "application/json")))
                {
                    EnrollmentResponse response;
                    _logger.LogTrace(JsonConvert.SerializeObject(enrollmentRequest));
                    var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
                    if (resp.StatusCode == HttpStatusCode.BadRequest) //DigiCert Sends Errors back in 400 Json Response
                    {
                        var errorResponse =
                            JsonConvert.DeserializeObject<ErrorList>(await resp.Content.ReadAsStringAsync(),
                                settings);
                        response = new EnrollmentResponse { RegistrationError = errorResponse, Result = null };
                        return response;
                    }

                    var registrationResponse =
                        JsonConvert.DeserializeObject<EnrollmentSuccessResponse>(await resp.Content.ReadAsStringAsync(),
                            settings);
                    response = new EnrollmentResponse { RegistrationError = null, Result = registrationResponse };
                    return response;
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"SubmitEnrollmentAsync Error Occurred {e.Message}");
                throw;
            }
        }

        public async Task<List<CertificateProfile>> SubmitGetProfilesAsync()
        {
            try
            {
                using (var resp = await RestClient.GetAsync("/mpki/api/v1/profile"))
                {
                    List<CertificateProfile> response;
                    var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
                    response =
                        JsonConvert.DeserializeObject<List<CertificateProfile>>(await resp.Content.ReadAsStringAsync(),
                            settings);
                    return response;
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"SubmitEnrollmentAsync Error Occurred {e.Message}");
                throw;
            }
        }

        public async Task<EnrollmentResponse> SubmitRenewalAsync(string serialNumber,
            EnrollmentRequest renewalRequest)
        {
            try
            {
                using (var resp = await RestClient.PostAsync($"/mpki/api/v1/certificate/{serialNumber}/renew",
                    new StringContent(
                        JsonConvert.SerializeObject(renewalRequest), Encoding.ASCII, "application/json")))
                {
                    EnrollmentResponse response;
                    _logger.LogTrace(JsonConvert.SerializeObject(renewalRequest));
                    var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
                    if (resp.StatusCode == HttpStatusCode.BadRequest) //DigiCert Sends Errors back in 400 Json Response
                    {
                        var errorResponse =
                            JsonConvert.DeserializeObject<ErrorList>(await resp.Content.ReadAsStringAsync(),
                                settings);
                        response = new EnrollmentResponse { RegistrationError = errorResponse, Result = null };
                        return response;
                    }

                    var registrationResponse =
                        JsonConvert.DeserializeObject<EnrollmentSuccessResponse>(await resp.Content.ReadAsStringAsync(),
                            settings);
                    response = new EnrollmentResponse { RegistrationError = null, Result = registrationResponse };
                    return response;
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"SubmitRenewalAsync Error Occurred {e.Message}");
                throw;
            }
        }

        public async Task<RevokeResponse> SubmitRevokeCertificateAsync(string serialNumber, RevokeRequest revokeRequest)
        {
            try
            {
                var response = new RevokeResponse();

                using (var resp = await RestClient.PutAsync($"/mpki/api/v1/certificate/{serialNumber}/revoke",
                    new StringContent(
                        JsonConvert.SerializeObject(revokeRequest), Encoding.ASCII, "application/json")))
                {
                    var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
                    if (resp.StatusCode == HttpStatusCode.BadRequest) //DigiCert Sends Errors back in 400 Json Response
                    {
                        var errorResponse =
                            JsonConvert.DeserializeObject<ErrorList>(await resp.Content.ReadAsStringAsync(),
                                settings);
                        response.RegistrationError = errorResponse;
                        response.Result = null;
                        return response;
                    }

                    var getRevokeResponse = await resp.Content.ReadAsStringAsync();
                    response = new RevokeResponse { RegistrationError = null, Result = getRevokeResponse };
                    return response;
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"SubmitRevokeCertificateAsync Error Occurred {e.Message}");
                throw;
            }
        }

        public async Task<GetCertificateResponse> SubmitGetCertificateAsync(string serialNumber)
        {
            try
            {
                using (var resp = await RestClient.GetAsync($"/mpki/api/v1/certificate/{serialNumber}"))
                {
                    _logger.LogTrace(JsonConvert.SerializeObject(resp));

                    var settings = new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore };
                    GetCertificateResponse response;
                    if (resp.StatusCode == HttpStatusCode.BadRequest) //DigiCert Sends Errors back in 400 Json Response
                    {
                        var errorResponse =
                            JsonConvert.DeserializeObject<ErrorList>(await resp.Content.ReadAsStringAsync(),
                                settings);
                        response = new GetCertificateResponse { CertificateError = errorResponse, Result = null };
                        return response;
                    }

                    var certificateResponse =
                        JsonConvert.DeserializeObject<CertificateDetails>(await resp.Content.ReadAsStringAsync(),
                            settings);
                    response = new GetCertificateResponse { CertificateError = null, Result = certificateResponse };
                    return response;
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"SubmitGetCertificateAsync Error Occurred {e.Message}");
                throw;
            }
        }

        public searchCertificateResponse SubmitQueryOrderRequest(
            RequestManager requestManager, string template, int pageCounter)
        {
            try
            {
                _logger.LogTrace($"Processing Template {template}");

                var queryOrderRequest =
                    requestManager.GetSearchCertificatesRequest(pageCounter, template);
                XmlSerializer x = new XmlSerializer(queryOrderRequest.GetType());
                TextWriter tw = new StringWriter();
                x.Serialize(tw, queryOrderRequest);
                _logger.LogTrace($"Raw Search Cert Soap Request {tw}");

                var bind = new BasicHttpsBinding { MaxReceivedMessageSize = 2147483647 };
                bind.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
                var ep = new EndpointAddress(EndPointAddress);
                var client = new certificateManagementOperationsClient(bind, ep);
                var cert = new X509Certificate2(ClientCertificateLocation, ClientCertificatePassword);
                if (client.ClientCredentials != null)
                    client.ClientCredentials.ClientCertificate.Certificate = cert;

                var resp = client.searchCertificate(queryOrderRequest);

                _logger.MethodExit();

                return resp;
            }
            catch (Exception e)
            {
                _logger.LogError($"CertificateSearchResultType Error Occurred {e.Message}");
                throw;
            }
        }

        private HttpClient ConfigureRestClient()
        {
            try
            {
                var clientHandler = new HttpClientHandler();
                var returnClient = new HttpClient(clientHandler, true) { BaseAddress = BaseUrl };
                returnClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                returnClient.DefaultRequestHeaders.Add("x-api-key", ApiKey);
                return returnClient;
            }
            catch (Exception e)
            {
                _logger.LogError($"ConfigureRestClient Error Occurred {e.Message}");
                throw;
            }
        }

        public static Dictionary<string, string> ExtractProfileIdsFromJson(string directoryPath)
        {
            Dictionary<string, string> profileIds = new Dictionary<string, string>();

            // Check if the directory exists
            if (!Directory.Exists(directoryPath))
            {
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");
            }

            // Get all JSON files in the directory
            string[] jsonFiles = Directory.GetFiles(directoryPath, "*.json");

            // Loop through each JSON file
            foreach (string jsonFile in jsonFiles)
            {
                try
                {
                    // Read the JSON file content
                    string jsonContent = File.ReadAllText(jsonFile);

                    // Parse the JSON content
                    JObject jsonObject = JObject.Parse(jsonContent);

                    // Check if the "profile" and "id" fields exist and are valid
                    var profileObject = jsonObject["profile"];
                    string? profileId = profileObject?["id"]?.ToString();

                    // If the profile id is valid, add it to the dictionary
                    if (!string.IsNullOrEmpty(profileId))
                    {
                        profileIds.Add(jsonFile, profileId);
                    }
                    else
                    {
                        // Log or note that the file does not match the expected pattern
                        Console.WriteLine($"File {jsonFile} does not follow the expected pattern. Skipping...");
                    }
                }
                catch (Exception ex)
                {
                    // Handle errors (like invalid JSON) and skip this file
                    Console.WriteLine($"Error processing file {jsonFile}: {ex.Message}. Skipping...");
                }
            }

            return profileIds;
        }

        public static Dictionary<string, string> ExtractEnrollmentParamsFromJson(string directoryPath)
        {
            Dictionary<string, string> enrollmentParams = new Dictionary<string, string>();

            // Check if the directory exists
            if (!Directory.Exists(directoryPath))
            {
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");
            }

            // Get all JSON files in the directory
            string[] jsonFiles = Directory.GetFiles(directoryPath, "*.json");

            // Loop through each JSON file
            foreach (string jsonFile in jsonFiles)
            {
                try
                {
                    // Read the JSON file content
                    string jsonContent = File.ReadAllText(jsonFile);

                    // Parse the JSON content
                    JObject jsonObject = JObject.Parse(jsonContent);

                    // Recursively search through the JSON structure for EnrollmentParams
                    ExtractParamsFromJsonObject(jsonObject, enrollmentParams);
                }
                catch (Exception ex)
                {
                    // Handle errors (like invalid JSON) and skip this file
                    Console.WriteLine($"Error processing file {jsonFile}: {ex.Message}. Skipping...");
                }
            }

            return enrollmentParams;
        }

        private static void ExtractParamsFromJsonObject(JToken jsonToken, Dictionary<string, string> enrollmentParams)
        {
            if (jsonToken is JObject)
            {
                foreach (var property in ((JObject)jsonToken).Properties())
                {
                    // Check the value of the property for EnrollmentParam pattern
                    string propertyValue = property.Value.ToString();

                    if (propertyValue.StartsWith("EnrollmentParam|") || propertyValue.StartsWith("Numeric|EnrollmentParam|"))
                    {
                        // Get the param name and type
                        string paramName = ExtractParamName(propertyValue);
                        string paramType = propertyValue.Contains("Numeric|") ? "Number" : "String";

                        // Add it to the dictionary only if it's not already present
                        if (!enrollmentParams.ContainsKey(paramName))
                        {
                            enrollmentParams[paramName] = paramType;
                            Console.WriteLine($"Found EnrollmentParam: {paramName}, Data Type: {paramType}");
                        }
                    }

                    // Recursively search for EnrollmentParams in nested objects
                    ExtractParamsFromJsonObject(property.Value, enrollmentParams);
                }
            }
            else if (jsonToken is JArray)
            {
                foreach (var item in jsonToken)
                {
                    ExtractParamsFromJsonObject(item, enrollmentParams);
                }
            }
        }

        private static string ExtractParamName(string enrollmentParam)
        {
            // Extract the name between "EnrollmentParam|" and "|Numeric" or simply after "EnrollmentParam|"
            var parts = enrollmentParam.Split('|');
            if (parts.Length == 2 && parts[0] == "EnrollmentParam")
            {
                return parts[1]; // Get the parameter name (e.g., "Validity (Years)")
            }

            if (parts.Length == 4 && parts[0] == "Numeric" && parts[1] == "EnrollmentParam")
            {
                return parts[2]; // Get the parameter name (e.g., "Validity (Years)")
            }

            return parts.Length > 1 ? parts[1] : "Unknown";
        }

    }
}
