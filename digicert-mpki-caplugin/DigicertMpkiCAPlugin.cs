using Keyfactor.AnyGateway.DigiCertSym;
using Keyfactor.AnyGateway.DigiCertSym.Client.Models;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.DigicertMpki.Client;
using Keyfactor.Logging;
using Keyfactor.PKI;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;


namespace Keyfactor.Extensions.CAPlugin.DigicertMpki
{
    public class DigicertMpkiCAPlugin : IAnyCAPlugin
    {
        private DigicertMpkiConfig _config;
        private readonly ILogger _logger;
        private ICertificateDataReader _certificateDataReader;
        private RequestManager _requestManager;
        private DigiCertSymClient _client;

        private Dictionary<int, string> DCVTokens { get; } = new Dictionary<int, string>();

        public DigicertMpkiCAPlugin()
        {
            _logger = LogHandler.GetClassLogger<DigicertMpkiCAPlugin>();
        }

        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _certificateDataReader = certificateDataReader;
            string rawConfig = JsonConvert.SerializeObject(configProvider.CAConnectionData);
            _config = JsonConvert.DeserializeObject<DigicertMpkiConfig>(rawConfig);

            _logger.MethodEntry();

            var connectors = GetCAConnectorAnnotations();


            _requestManager = new RequestManager(_logger, _config);

            _client = new DigiCertSymClient(_config, _logger);
            //Templates = config.Config.Templates;

            _logger.MethodExit();
        }


        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            try
            {
                _logger.MethodEntry();
                if (string.IsNullOrEmpty(caRequestID))
                    return null;

                var keyfactorCaId = caRequestID;
                _logger.LogTrace($"Keyfactor Ca Id: {keyfactorCaId}");
                var certificateResponse =
                    Task.Run(async () => await _client.SubmitGetCertificateAsync(keyfactorCaId))
                        .Result;

                _logger.LogTrace($"Single Cert JSON: {JsonConvert.SerializeObject(certificateResponse)}");
                _logger.MethodExit();

                return new AnyCAPluginCertificate
                {
                    CARequestID = keyfactorCaId,
                    Certificate = certificateResponse.Result.Certificate,
                    Status = _requestManager.MapReturnStatus(certificateResponse.Result.Status)
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"GetSingleRecord Error Occurred: {e.Message}");
                throw;
            }
        }

        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            try
            {
                //Only Full Sync is Supported so check for it.
                if (fullSync)
                {
                    //Loop through all the Digicert Profile OIDs that are setup in the config file
                    foreach (var productModel in GetProductIds())
                    {

                        var pageCounter = 0;
                        var pageSize = 50;
                        var result =
                            _client.SubmitQueryOrderRequest(_requestManager, productModel, pageCounter);
                        var totalResults = result.searchCertificateResponse1.certificateCount;
                        var totalPages = (totalResults + pageSize - 1) / pageSize;

                        _logger.LogTrace(
                            $"Product Model {productModel} Total Results {totalResults}, Total Pages {totalPages}");

                        if (result.searchCertificateResponse1.certificateCount > 0)
                        {
                            for (var i = 0; i < totalPages; i++)
                            {
                                //If you need multiple pages make the request again
                                if (pageCounter > 0)
                                {
                                    result = _client.SubmitQueryOrderRequest(_requestManager, productModel,
                                        pageCounter);
                                }

                                XmlSerializer x = new XmlSerializer(result.GetType());
                                TextWriter tw = new StringWriter();
                                x.Serialize(tw, result);
                                _logger.LogTrace($"Raw Search Cert Soap Response {tw}");

                                foreach (var currentResponseItem in result.searchCertificateResponse1.certificateList)
                                {
                                    try
                                    {
                                        _logger.LogTrace(
                                            $"Took Certificate ID {currentResponseItem?.serialNumber} from Queue");

                                        if (currentResponseItem != null)
                                        {
                                            var certStatus =
                                                _requestManager.MapReturnStatus(currentResponseItem.status);
                                            _logger.LogTrace($"Certificate Status {certStatus}");

                                            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                                            var base64Cert = Convert.ToBase64String(currentResponseItem.certificate);
                                            try
                                            {
                                                var currentCert =
                                                    new System.Security.Cryptography.X509Certificates.X509Certificate2(
                                                        Encoding.ASCII.GetBytes(base64Cert));
                                                blockingBuffer.Add(new AnyCAPluginCertificate
                                                {
                                                    CARequestID =
                                                        $"{currentResponseItem.serialNumber}",
                                                    Certificate = base64Cert,
                                                    Status = certStatus,
                                                    ProductID = $"{currentResponseItem.profileOID}",
                                                    RevocationReason =
                                                        _requestManager.MapSoapRevokeReason(currentResponseItem
                                                            .revokeReason)
                                                }, cancelToken);
                                            }
                                            catch (Exception e)
                                            {
                                                _logger.LogWarning(
                                                    $"Invalid Certificate, skipping this one {LogHandler.FlattenException(e)}");
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException e)
                                    {
                                        _logger.LogError($"Synchronize was canceled. {e.Message}");
                                        break;
                                    }
                                }

                                pageCounter += pageSize;
                            }
                        }
                    }
                }
            }
            catch (AggregateException aggEx)
            {
                _logger.LogError("Digicert mPKI Synchronize Task failed!");
                _logger.MethodExit();
                // ReSharper disable once PossibleIntendedRethrow
                throw aggEx;
            }

            _logger.MethodExit();
        }

        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            try
            {
                _logger.LogTrace("Staring Revoke Method");
                //Digicert can't find serial numbers with leading zeros
                hexSerialNumber = hexSerialNumber.TrimStart(new char[] { '0' });
                var revokeRequest = _requestManager.GetRevokeRequest(revocationReason);

                var revokeResponse =
                    Task.Run(async () =>
                            await _client.SubmitRevokeCertificateAsync(hexSerialNumber, revokeRequest))
                        .Result;

                _logger.LogTrace($"Revoke Response JSON: {JsonConvert.SerializeObject(revokeResponse)}");

                var revokeResult = _requestManager.GetRevokeResult(revokeResponse);

                if (revokeResult == Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.FAILED))
                    throw new Exception("Revoke failed");

                return revokeResult;
            }
            catch (Exception e)
            {
                _logger.LogError($"Revoke Error Occurred: {e.Message}");
                throw;
            }
        }

        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();

            EnrollmentRequest enrollmentRequest;
            EnrollmentRequest renewRequest;

            try
            {
                var productList = GetProductList();
                switch (enrollmentType)
                {
                    case EnrollmentType.New:
                        _logger.LogTrace("Entering New Enrollment");
                        //If they renewed an expired cert it gets here and this will not be supported

                        enrollmentRequest = _requestManager.GetEnrollmentRequest(productInfo, csr, san, productList);
                        _logger.LogTrace($"Enrollment Request JSON: {JsonConvert.SerializeObject(enrollmentRequest)}");
                        var enrollmentResponse =
                            Task.Run(async () => await _client.SubmitEnrollmentAsync(enrollmentRequest))
                                .Result;

                        if (enrollmentResponse?.Result == null)
                            return new EnrollmentResult
                            {
                                Status = (int)EndEntityStatus.FAILED, //failure
                                StatusMessage =
                                    $"Enrollment Failed: {_requestManager.FlattenErrors(enrollmentResponse?.RegistrationError.Errors)}"
                            };


                        _logger.LogTrace($"Enrollment Response JSON: {JsonConvert.SerializeObject(enrollmentResponse)}");

                        _logger.MethodExit();

                        var cert = GetSingleRecord(enrollmentResponse.Result.SerialNumber);
                        return _requestManager.GetEnrollmentResult(enrollmentResponse, cert.Result);
                    case EnrollmentType.Renew:
                    case EnrollmentType.RenewOrReissue:
                        _logger.LogTrace("Entering Renew Enrollment");
                        _logger.LogTrace("Checking To Make sure it is not one click renew (not supported)");
                        //KeyFactor needs a better way to detect one click renewals, some flag or something

                        var priorCertSn = productInfo.ProductParameters["PriorCertSN"];
                        _logger.LogTrace($"Renew Serial Number: {priorCertSn}");
                        renewRequest = _requestManager.GetEnrollmentRequest(productInfo, csr, san, productList);

                        _logger.LogTrace($"Renewal Request JSON: {JsonConvert.SerializeObject(renewRequest)}");
                        var renewResponse = Task.Run(async () =>
                                await _client.SubmitRenewalAsync(priorCertSn, renewRequest))
                            .Result;
                        if (renewResponse?.Result == null)
                            return new EnrollmentResult
                            {
                                Status = (int)EndEntityStatus.FAILED, //failure
                                StatusMessage =
                                    $"Enrollment Failed {_requestManager.FlattenErrors(renewResponse?.RegistrationError.Errors)}"
                            };

                        _logger.MethodExit();
                        var renCert = GetSingleRecord(renewResponse.Result.SerialNumber);
                        return _requestManager.GetRenewResponse(renewResponse, renCert.Result);


                }

                _logger.MethodExit();
                return null;
            }
            catch (Exception e)
            {
                _logger.LogError($"Enrollment Error Occurred: {e.Message}");
                throw;
            }
        }

        public async Task Ping()
        {
            _logger.MethodEntry(LogLevel.Trace);
            _logger.MethodExit(LogLevel.Trace);
        }

        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.LogInformation("Validation successful");

            List<string> errors = new List<string>();

            _logger.LogTrace("Checking the API Key.");
            string apiKey = connectionInfo.ContainsKey(Constants.DigiCertSymApiKey) ? (string)connectionInfo[Constants.DigiCertSymApiKey] : string.Empty;
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                errors.Add("The API Key is required.");
            }

            _logger.LogTrace("Checking the Base URL.");
            string baseURL = connectionInfo.ContainsKey(Constants.DigiCertSymUrl) ? (string)connectionInfo[Constants.DigiCertSymUrl] : string.Empty;
            if (string.IsNullOrWhiteSpace(baseURL))
            {
                errors.Add("The Base URL is Empty and required.");
            }
            else if (!baseURL.Contains("https"))
            {
                errors.Add("The Base URL needs https://");
            }

            _logger.LogTrace("Checking the SOAP Endpoint Address.");
            string soapEndpoint = connectionInfo.ContainsKey(Constants.EndpointAddress) ? (string)connectionInfo[Constants.EndpointAddress] : string.Empty;
            if (string.IsNullOrWhiteSpace(soapEndpoint))
            {
                errors.Add("The SOAP URL is Empty and required.");
            }
            else if (!soapEndpoint.Contains("https"))
            {
                errors.Add("The SOAP URL needs https://");
            }

            _logger.LogTrace("Checking the Client Certificate Location.");
            string clientCertLocation = connectionInfo.ContainsKey(Constants.ClientCertLocation) ? (string)connectionInfo[Constants.ClientCertLocation] : string.Empty;
            if (string.IsNullOrWhiteSpace(clientCertLocation))
            {
                errors.Add("The Client Certificate Location Is a required value.");
            }
            _logger.LogTrace("Checking the Client Certificate Password.");
            string clientCertPassword = connectionInfo.ContainsKey(Constants.ClientCertPassword) ? (string)connectionInfo[Constants.ClientCertPassword] : string.Empty;
            if (string.IsNullOrWhiteSpace(clientCertPassword))
            {
                errors.Add("The Client Certificate Password Is a required value.");
            }

            _logger.LogTrace("Checking the DNS Constant Name.");
            string DnsConstantName = connectionInfo.ContainsKey(Constants.DnsConstName) ? (string)connectionInfo[Constants.DnsConstName] : string.Empty;
            if (string.IsNullOrWhiteSpace(clientCertPassword))
            {
                errors.Add("The DNS Constant Name is a required value.");
            }

            if (errors.Any())
            {
                ThrowValidationException(errors);
            }
        }

        private void ThrowValidationException(List<string> errors)
        {
            string validationMsg = $"Validation errors:\n{string.Join("\n", errors)}";
            throw new AnyCAValidationException(validationMsg);
        }

        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.LogInformation("Product Info validated successfully");
            return Task.CompletedTask;
        }

        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.DigiCertSymApiKey] = new PropertyConfigInfo()
                {
                    Comments = "Digicert mPKI Rest API Key",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.DigiCertSymUrl] = new PropertyConfigInfo()
                {
                    Comments = "Base Url for Digicert mPKI REST API such as https://someurl/mpki/api/v1",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.ClientCertLocation] = new PropertyConfigInfo()
                {
                    Comments = "Location on the Gateway Server File System of Client Certificate sample: C:\\temp\\myclientcert.pfx",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.ClientCertPassword] = new PropertyConfigInfo()
                {
                    Comments = "Password for the SOAP Client Certificate.",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.EndpointAddress] = new PropertyConfigInfo()
                {
                    Comments = "Endpoint address for SOAP Service sample: https://someurl/pki-ws/certificateManagementService.",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                [Constants.DnsConstName] = new PropertyConfigInfo()
                {
                    Comments = "Name of the constant DNS Name that digicert expects in the API.",
                    Hidden = false,
                    DefaultValue = "dnsName",
                    Type = "String"
                },
                [Constants.UpnConstName] = new PropertyConfigInfo()
                {
                    Comments = "Name of the constant Upn name that digicert expects in the API.",
                    Hidden = false,
                    DefaultValue = "otherNameUPN",
                    Type = "String"
                },
                [Constants.IpConstName] = new PropertyConfigInfo()
                {
                    Comments = "Name of the constant Ip San Name that digicert expects in the API.",
                    Hidden = false,
                    DefaultValue = "san_ipAddress",
                    Type = "String"
                },
                [Constants.EmailConstName] = new PropertyConfigInfo()
                {
                    Comments = "Name of the constant Email Name that digicert expects in the API.",
                    Hidden = false,
                    DefaultValue = "mail_email",
                    Type = "String"
                },
                [Constants.OuStartPoint] = new PropertyConfigInfo()
                {
                    Comments = "Value of the OuStartPoint Name that digicert expects in the API.",
                    Hidden = false,
                    DefaultValue = 0,
                    Type = "Number"
                }

            };
        }

        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            var templateParams = new Dictionary<string, PropertyConfigInfo>();

            _logger.LogTrace("Getting File Execution Location to retrieve path");
            string codeBase = Assembly.GetExecutingAssembly().Location;
            UriBuilder uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            path = Path.GetDirectoryName(path) + "\\";
            _logger.LogTrace($"Executing path for the file is: {path}");

            var paramList = DigiCertSymClient.ExtractEnrollmentParamsFromJson(path);


            foreach (var param in paramList)
            {
                var propConfig = GeneratePropertyConfig(param);
                templateParams.Add(param.Key, propConfig);
            }

            return templateParams;
        }

        private PropertyConfigInfo GeneratePropertyConfig(KeyValuePair<string, string> param)
        {
            return new PropertyConfigInfo()
            {
                Comments = "",
                Hidden = false,
                DefaultValue = "",
                Type = param.Value,
            };

        }

        public List<string> GetProductIds()
        {
            var productIds = GetProductList();
            return productIds.Values.ToList();
        }

        private Dictionary<string, string> GetProductList()
        {
            _logger.LogTrace("Getting File Execution Location to retrieve path");
            string codeBase = Assembly.GetExecutingAssembly().Location;
            UriBuilder uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            path = Path.GetDirectoryName(path) + "\\";
            _logger.LogTrace($"Executing path for the file is: {path}");

            var productIds = DigiCertSymClient.ExtractProfileIdsFromJson(path);

            return productIds;

        }


        Task<AnyCAPluginCertificate> IAnyCAPlugin.GetSingleRecord(string caRequestID)
        {
            throw new NotImplementedException();
        }

    }
}

