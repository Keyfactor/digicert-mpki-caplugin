using DigicertMpkiSoap;
using Keyfactor.AnyGateway.DigicertMpki;
using Keyfactor.AnyGateway.DigicertMpki.Client.Models;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.DigicertMpki.Client;
using Keyfactor.Extensions.CAPlugin.DigicertMpki.Models;
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
            _config = DeserializeConfig(configProvider.CAConnectionData);
            _logger.MethodEntry();

            _requestManager = new RequestManager(_logger, _config);
            _client = new DigiCertSymClient(_config, _logger);

            _logger.MethodExit();
        }

        private DigicertMpkiConfig DeserializeConfig(Dictionary<string, object> configData)
        {
            string rawConfig = JsonConvert.SerializeObject(configData);
            return JsonConvert.DeserializeObject<DigicertMpkiConfig>(rawConfig);
        }

        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            if (string.IsNullOrEmpty(caRequestID))
            {
                _logger.LogWarning("CA Request ID is null or empty.");
                return null;
            }

            try
            {
                _logger.MethodEntry();
                var certificateResponse = await _client.SubmitGetCertificateAsync(caRequestID);
                _logger.LogTrace($"Single Cert JSON: {JsonConvert.SerializeObject(certificateResponse)}");

                _logger.MethodExit();
                return new AnyCAPluginCertificate
                {
                    CARequestID = caRequestID,
                    Certificate = certificateResponse?.Result?.Certificate,
                    Status = _requestManager.MapReturnStatus(certificateResponse?.Result?.Status)
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Error retrieving single record: {e.Message}");
                throw;
            }
        }

        public async Task Synchronize(BlockingCollection<AnyCAPluginCertificate> blockingBuffer, DateTime? lastSync, bool fullSync, CancellationToken cancelToken)
        {
            if (!fullSync)
            {
                _logger.LogWarning("Partial synchronization is not supported.");
                return;
            }

            try
            {
                foreach (var productModel in GetProductIds())
                {
                    await ProcessProductModel(productModel, blockingBuffer, cancelToken);
                }
            }
            catch (Exception e)
            {
                _logger.LogError($"Synchronization failed: {e.Message}");
                throw;
            }
        }

        private async Task ProcessProductModel(string productModel, BlockingCollection<AnyCAPluginCertificate> blockingBuffer, CancellationToken cancelToken)
        {
            int pageCounter = 0;
            const int pageSize = 50;

            var result = _client.SubmitQueryOrderRequest(_requestManager, productModel, pageCounter);
            int totalResults = result.searchCertificateResponse1.certificateCount;
            int totalPages = (totalResults + pageSize - 1) / pageSize;

            _logger.LogTrace($"Product {productModel} Total Results: {totalResults}, Total Pages: {totalPages}");

            for (int i = 0; i < totalPages; i++)
            {
                if (pageCounter > 0)
                    result = _client.SubmitQueryOrderRequest(_requestManager, productModel, pageCounter);

                LogSoapResponse(result);
                var certificateList = result.searchCertificateResponse1.certificateList ?? new CertificateSearchResultType[0];

                foreach (var currentResponseItem in certificateList)
                {
                    if (currentResponseItem == null) continue;

                    try
                    {
                        var certStatus = _requestManager.MapReturnStatus(currentResponseItem.status);
                        _logger.LogTrace($"Certificate Status: {certStatus}");

                        var base64Cert = Convert.ToBase64String(currentResponseItem.certificate);
                        var currentCert = new System.Security.Cryptography.X509Certificates.X509Certificate2(Encoding.ASCII.GetBytes(base64Cert));

                        blockingBuffer.Add(new AnyCAPluginCertificate
                        {
                            CARequestID = currentResponseItem.serialNumber,
                            Certificate = base64Cert,
                            Status = certStatus,
                            ProductID = currentResponseItem.profileOID,
                            RevocationReason = _requestManager.MapSoapRevokeReason(currentResponseItem.revokeReason)
                        }, cancelToken);
                    }
                    catch (Exception e)
                    {
                        _logger.LogWarning($"Invalid certificate, skipping. Error: {LogHandler.FlattenException(e)}");
                    }
                }

                pageCounter += pageSize;
            }
        }

        private void LogSoapResponse(object result)
        {
            XmlSerializer x = new XmlSerializer(result.GetType());
            using (TextWriter tw = new StringWriter())
            {
                x.Serialize(tw, result);
                _logger.LogTrace($"Raw Search Cert SOAP Response: {tw}");
            }
        }

        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            try
            {
                _logger.LogTrace("Starting Revoke Method");
                hexSerialNumber = hexSerialNumber.TrimStart('0');
                var revokeRequest = _requestManager.GetRevokeRequest(revocationReason);

                var revokeResponse = await _client.SubmitRevokeCertificateAsync(hexSerialNumber, revokeRequest);
                _logger.LogTrace($"Revoke Response JSON: {JsonConvert.SerializeObject(revokeResponse)}");

                return _requestManager.GetRevokeResult(revokeResponse);
            }
            catch (Exception e)
            {
                _logger.LogError($"Revoke Error: {e.Message}");
                throw;
            }
        }

        public async Task<EnrollmentResult> Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, RequestFormat requestFormat, EnrollmentType enrollmentType)
        {
            _logger.MethodEntry();

            try
            {
                var productList = GetProductList();
                return enrollmentType switch
                {
                    EnrollmentType.New => await ProcessNewEnrollment(csr, san, productInfo, productList),
                    EnrollmentType.Renew or EnrollmentType.RenewOrReissue => await ProcessRenewEnrollment(csr, productInfo, san),
                    _ => throw new NotSupportedException("Unsupported enrollment type")
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Enrollment Error: {e.Message}");
                throw;
            }
        }

        private async Task<EnrollmentResult> ProcessNewEnrollment(string csr, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, Dictionary<string, string> productList)
        {
            _logger.LogTrace("Entering New Enrollment");
            var profiles = await _client.SubmitGetProfilesAsync();

            var sanAttributes=GetSanAttributesByProfile(profiles);

            var enrollmentRequest = _requestManager.GetEnrollmentRequest(productInfo, csr, san, productList,sanAttributes, profiles);

            _logger.LogTrace($"Enrollment Request JSON: {JsonConvert.SerializeObject(enrollmentRequest)}");
            var enrollmentResponse = await _client.SubmitEnrollmentAsync(enrollmentRequest);

            if (enrollmentResponse?.Result == null)
                return EnrollmentFailedResult(_requestManager.FlattenErrors(enrollmentResponse?.RegistrationError.Errors));

            var cert = await GetSingleRecord(enrollmentResponse.Result.SerialNumber);
            return _requestManager.GetEnrollmentResult(enrollmentResponse, cert);
        }

        public static Dictionary<Tuple<string, string>, string> GetSanAttributesByProfile(List<CertificateProfile> profiles)
        {
            // Collect all attribute IDs from the SAN extensions
            Dictionary<Tuple<string, string>, string> attributeIds = new Dictionary<Tuple<string, string>, string>();

            try
            {
                foreach (var profile in profiles)
                {
                    // Check if the certificate and extensions are not null
                    if (profile.Certificate?.Extensions?.San?.Attributes != null)
                    {
                        foreach (var attribute in profile.Certificate.Extensions.San.Attributes)
                        {
                            if (!string.IsNullOrEmpty(attribute.Id))
                            {
                                var attType=attribute.Type;

                                if(attributeIds.ContainsKey(Tuple.Create(profile.Id, attribute.Type)) && attribute.Id.Contains("_multi"))
                                {
                                    attType= attribute.Type + "_multi";
                                }
                                attributeIds.Add(Tuple.Create(profile.Id, attType), attribute.Id);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions here, for example, by logging the error
                Console.WriteLine($"An error occurred while processing SAN attributes: {ex.Message}");
                // Optionally, you can rethrow the exception if needed
                // throw;
            }

            return attributeIds;
        }


        private async Task<EnrollmentResult> ProcessRenewEnrollment(string csr, EnrollmentProductInfo productInfo, Dictionary<string, string[]> san)
        {
            _logger.LogTrace("Entering Renew Enrollment");
            string priorCertSn = productInfo.ProductParameters["PriorCertSN"];
            _logger.LogTrace($"Renew Serial Number: {priorCertSn}");

            var profiles = await _client.SubmitGetProfilesAsync();

            var sanAttributes = GetSanAttributesByProfile(profiles);

            var renewRequest = _requestManager.GetEnrollmentRequest(productInfo, csr, san, GetProductList(),sanAttributes, profiles);
            _logger.LogTrace($"Renewal Request JSON: {JsonConvert.SerializeObject(renewRequest)}");

            var renewResponse = await _client.SubmitRenewalAsync(priorCertSn, renewRequest);
            if (renewResponse?.Result == null)
                return EnrollmentFailedResult(_requestManager.FlattenErrors(renewResponse?.RegistrationError.Errors));

            var renCert = await GetSingleRecord(renewResponse.Result.SerialNumber);
            return _requestManager.GetRenewResponse(renewResponse, renCert);
        }

        private EnrollmentResult EnrollmentFailedResult(string errorMessage) => new EnrollmentResult
        {
            Status = (int)EndEntityStatus.FAILED,
            StatusMessage = $"Enrollment Failed: {errorMessage}"
        };

        public async Task Ping() => _logger.LogTrace("Ping successful.");

        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            List<string> errors = ValidateConnectionInfo(connectionInfo);
            if (errors.Any())
                ThrowValidationException(errors);

            _logger.LogInformation("Validation successful");
        }

        private List<string> ValidateConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            var errors = new List<string>();

            CheckRequiredField(connectionInfo, Constants.DigiCertSymApiKey, "API Key", errors);
            CheckRequiredField(connectionInfo, Constants.DigiCertSymUrl, "Base URL", errors, url => !url.Contains("https"), "The Base URL needs https://");
            CheckRequiredField(connectionInfo, Constants.EndpointAddress, "SOAP Endpoint", errors, url => !url.Contains("https"), "The SOAP URL needs https://");
            CheckRequiredField(connectionInfo, Constants.ClientCertLocation, "Client Certificate Location", errors);
            CheckRequiredField(connectionInfo, Constants.ClientCertPassword, "Client Certificate Password", errors);

            return errors;
        }

        private void CheckRequiredField(Dictionary<string, object> connectionInfo, string key, string fieldName, List<string> errors, Func<string, bool> condition = null, string conditionMessage = null)
        {
            string value = connectionInfo.ContainsKey(key) ? connectionInfo[key]?.ToString() : string.Empty;
            if (string.IsNullOrWhiteSpace(value))
                errors.Add($"{fieldName} is required.");
            else if (condition != null && condition(value))
                errors.Add(conditionMessage);
        }

        private void ThrowValidationException(List<string> errors)
        {
            string validationMsg = $"Validation errors:\n{string.Join("\n", errors)}";
            throw new AnyCAValidationException(validationMsg);
        }

        public Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo) => Task.CompletedTask;

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
                }
            };
        }


        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            var path = GetExecutingPath();
            var paramList = DigiCertSymClient.ExtractEnrollmentParamsFromJson(path);

            return paramList.ToDictionary(param => param.Key, param => new PropertyConfigInfo
            {
                Comments = string.Empty,
                Hidden = false,
                Type = param.Value
            });
        }

        private string GetExecutingPath()
        {
            string codeBase = Assembly.GetExecutingAssembly().Location;
            UriBuilder uri = new UriBuilder(codeBase);
            string path = Uri.UnescapeDataString(uri.Path);
            return Path.GetDirectoryName(path) + "\\";
        }

        public List<string> GetProductIds() => GetProductList().Values.ToList();

        private Dictionary<string, string> GetProductList()
        {
            string path = GetExecutingPath();
            return DigiCertSymClient.ExtractProfileIdsFromJson(path);
        }
    }
}
