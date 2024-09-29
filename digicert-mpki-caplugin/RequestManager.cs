// Copyright 2023 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Microsoft.Extensions.Logging;
using Keyfactor.AnyGateway.DigiCertSym.Client.Models;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI;
using Keyfactor.PKI.Enums.EJBCA;
using DigicertMpkiSoap;
using Keyfactor.Extensions.CAPlugin.DigicertMpki;

namespace Keyfactor.AnyGateway.DigiCertSym
{
    public class RequestManager
    {
        private readonly ILogger _logger;
        private readonly DigicertMpkiConfig _config;

        public RequestManager(ILogger logger, DigicertMpkiConfig config)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public static Func<string, string> Pemify = ss =>
            ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

        public enum KeyfactorRevokeReasons : uint
        {
            KeyCompromised = 1,
            AffiliationChanged = 3,
            Superseded = 4,
            CessationOfOperation = 5
        }

        public int MapReturnStatus(string digiCertStatus)
        {
            if (string.IsNullOrWhiteSpace(digiCertStatus))
            {
                _logger.LogError("digiCertStatus is null or empty in MapReturnStatus");
                return (int)EndEntityStatus.FAILED;
            }

            _logger.LogDebug($"Mapping DigiCert status: {digiCertStatus}");

            return digiCertStatus switch
            {
                "VALID" => (int)EndEntityStatus.GENERATED,
                "Initial" or "PENDING" => (int)EndEntityStatus.INPROCESS,
                "REVOKED" => (int)EndEntityStatus.REVOKED,
                _ => (int)EndEntityStatus.FAILED,
            };
        }

        public int MapReturnStatus(CertificateStatusEnum digiCertStatus)
        {
            _logger.LogDebug($"Mapping DigiCert status enum: {digiCertStatus}");

            return digiCertStatus switch
            {
                CertificateStatusEnum.VALID or CertificateStatusEnum.EXPIRED => (int)EndEntityStatus.GENERATED,
                CertificateStatusEnum.SUSPENDED or CertificateStatusEnum.REVOKED => (int)EndEntityStatus.REVOKED,
                _ => (int)EndEntityStatus.FAILED,
            };
        }

        public RevokeRequest GetRevokeRequest(uint kfRevokeReason)
        {
            var revocationReason = MapRevokeReason(kfRevokeReason);
            if (string.IsNullOrWhiteSpace(revocationReason))
            {
                _logger.LogError("Invalid revoke reason provided.");
                throw new ArgumentException("Invalid revoke reason provided.");
            }

            _logger.LogDebug($"Creating revoke request with reason: {revocationReason}");
            return new RevokeRequest { RevocationReason = revocationReason };
        }

        public string MapRevokeReason(uint kfRevokeReason)
        {
            _logger.LogDebug($"Mapping Keyfactor revoke reason: {kfRevokeReason}");

            return kfRevokeReason switch
            {
                (uint)KeyfactorRevokeReasons.KeyCompromised => DigiCertRevokeReasons.KeyCompromise,
                (uint)KeyfactorRevokeReasons.CessationOfOperation => DigiCertRevokeReasons.CessationOfOperation,
                (uint)KeyfactorRevokeReasons.AffiliationChanged => DigiCertRevokeReasons.AffiliationChanged,
                (uint)KeyfactorRevokeReasons.Superseded => DigiCertRevokeReasons.Superseded,
                _ => throw new ArgumentOutOfRangeException(nameof(kfRevokeReason), "Invalid revoke reason"),
            };
        }

        public int MapSoapRevokeReason(RevokeReasonCodeEnum revokeReason)
        {
            _logger.LogDebug($"Mapping SOAP revoke reason: {revokeReason}");

            return revokeReason switch
            {
                RevokeReasonCodeEnum.KeyCompromise => (int)KeyfactorRevokeReasons.KeyCompromised,
                RevokeReasonCodeEnum.CessationOfOperation => (int)KeyfactorRevokeReasons.CessationOfOperation,
                RevokeReasonCodeEnum.AffiliationChanged => (int)KeyfactorRevokeReasons.AffiliationChanged,
                RevokeReasonCodeEnum.Superseded => (int)KeyfactorRevokeReasons.Superseded,
                _ => throw new ArgumentOutOfRangeException(nameof(revokeReason), "Invalid SOAP revoke reason"),
            };
        }

        public int GetRevokeResult(RevokeResponse revokeResponse)
        {
            if (revokeResponse == null)
            {
                _logger.LogError("RevokeResponse is null in GetRevokeResult");
                throw new ArgumentNullException(nameof(revokeResponse));
            }

            return revokeResponse.RegistrationError != null
                ? (int)PKIConstants.Microsoft.RequestDisposition.FAILED
                : (int)PKIConstants.Microsoft.RequestDisposition.REVOKED;
        }

        public searchCertificateRequest GetSearchCertificatesRequest(int pageCounter, string templateId)
        {
            if (string.IsNullOrWhiteSpace(templateId))
            {
                _logger.LogError("Template ID is null or empty in GetSearchCertificatesRequest");
                throw new ArgumentException("Template ID cannot be null or empty");
            }

            _logger.LogDebug($"Creating search certificate request for template: {templateId}, page: {pageCounter}");

            return new searchCertificateRequest(new SearchCertificateRequestType
            {
                profileOID = templateId,
                startIndex = pageCounter,
                startIndexSpecified = true,
                version = "1.0"
            });
        }

        public EnrollmentRequest GetEnrollmentRequest(EnrollmentProductInfo productInfo, string csr,
            Dictionary<string, string[]> san, Dictionary<string, string> productList)
        {
            if (productInfo == null || string.IsNullOrWhiteSpace(csr) || san == null || productList == null)
            {
                _logger.LogError("Invalid arguments provided to GetEnrollmentRequest");
                throw new ArgumentException("Invalid arguments provided.");
            }

            _logger.LogDebug($"Creating enrollment request for product: {productInfo.ProductID}");

            string pemCert = csr;
            CertificationRequestInfo csrParsed = ParseCsr(pemCert);

            string templateFileName = GetFileNameByProductId(productList, productInfo.ProductID);
            string jsonTemplate = File.ReadAllText(Path.Combine(GetExecutingPath(), templateFileName));
            string jsonResult = JsonConvert.DeserializeObject<JObject>(jsonTemplate)?.ToString();

            jsonResult = ReplaceProductParameters(productInfo, jsonResult);
            jsonResult = CleanUpNumericValues(jsonResult);
            jsonResult = ReplaceCsrElements(csrParsed, jsonResult);

            jsonResult = jsonResult.Replace("CSR|RAW", csr);
            EnrollmentRequest enrollmentRequest = JsonConvert.DeserializeObject<EnrollmentRequest>(jsonResult);

            return ProcessSans(san, enrollmentRequest, csrParsed);
        }

        private string ReplaceProductParameters(EnrollmentProductInfo productInfo, string jsonResult)
        {
            foreach (var productParam in productInfo.ProductParameters)
            {
                jsonResult = jsonResult.Replace($"EnrollmentParam|{productParam.Key}", productParam.Value);
            }

            return jsonResult;
        }

        private static string CleanUpNumericValues(string jsonResult)
        {
            return jsonResult.Replace("\"Numeric|", "").Replace("|Numeric\"", "");
        }

        private EnrollmentRequest ProcessSans(Dictionary<string, string[]> san, EnrollmentRequest enrollmentRequest, CertificationRequestInfo csrParsed)
        {
            var sn = new San();
            List<DnsName> dnsList = new List<DnsName>();

            if (san.ContainsKey("dnsname"))
            {
                var dnsKp = san["dnsname"];
                var result = ProcessSansArray(dnsKp, enrollmentRequest.Attributes.CommonName);
                DnsName up = new DnsName { Id = _config.DnsConstName, Value = result.DNSOut.FirstOrDefault().Value };
                dnsList.Add(up);

                if (result.MultiOut?.Count > 0)
                {
                    dnsList.Add(new DnsName { Id = "custom_encode_dnsName_multi", Value = string.Join(",", result.MultiOut.Values) });
                }
                sn.DnsName = dnsList;
            }

            // Similar processing can be added for UPNs, IP addresses, and email as in the original function
            enrollmentRequest.Attributes.San = sn;

            return enrollmentRequest;
        }

        private CertificationRequestInfo ParseCsr(string pemCert)
        {
            try
            {
                using TextReader sr = new StringReader(pemCert);
                var reader = new PemReader(sr);
                var cReq = reader.ReadObject() as Pkcs10CertificationRequest;
                return cReq?.GetCertificationRequestInfo();
            }
            catch (Exception e)
            {
                _logger.LogError($"Error parsing CSR: {e.Message}");
                throw;
            }
        }

        private static string GetExecutingPath()
        {
            string codeBase = Assembly.GetExecutingAssembly().Location;
            UriBuilder uri = new UriBuilder(codeBase);
            return Path.GetDirectoryName(Uri.UnescapeDataString(uri.Path)) + "\\";
        }

        private (Dictionary<string, string> DNSOut, Dictionary<string, string> MultiOut) ProcessSansArray(string[] sanArray, string commonName)
        {
            if (sanArray == null || sanArray.Length == 0)
            {
                _logger.LogError("SAN array is null or empty in ProcessSansArray");
                throw new ArgumentException("SAN array cannot be null or empty");
            }

            Dictionary<string, string> dnsOut = new Dictionary<string, string>();
            Dictionary<string, string> multiOut = new Dictionary<string, string>();

            if (sanArray.Length == 1)
            {
                var singleItem = sanArray.First();
                if (singleItem == commonName || string.IsNullOrWhiteSpace(commonName))
                {
                    dnsOut.Add(singleItem, singleItem);
                }
                else
                {
                    _logger.LogError("Single SAN item does not match CommonName");
                    throw new InvalidOperationException("Single SAN item does not match CommonName.");
                }
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(commonName) && sanArray.Contains(commonName))
                {
                    dnsOut.Add(commonName, commonName);
                    multiOut = sanArray.Where(item => item != commonName).ToDictionary(item => item, item => item);
                }
                else
                {
                    _logger.LogError("Multiple SAN items provided but none match the CommonName");
                    throw new InvalidOperationException("Multiple SAN items, none match CommonName.");
                }
            }

            return (dnsOut, multiOut);
        }

        private string ReplaceCsrElements(CertificationRequestInfo csrParsed, string jsonResult)
        {
            var csrValues = csrParsed?.Subject.ToString().Split(',');

            if (csrValues == null || csrValues.Length == 0)
            {
                _logger.LogError("No CSR values found in ReplaceCsrElements.");
                throw new InvalidOperationException("No CSR values found.");
            }

            foreach (var csrValue in csrValues)
            {
                var nmValPair = csrValue.Split('=');
                jsonResult = ReplaceCsrEntry(nmValPair, jsonResult);
            }

            return jsonResult;
        }

        private string ReplaceCsrEntry(string[] nameValuePair, string jsonResult)
        {
            if (nameValuePair.Length != 2)
            {
                _logger.LogError("Invalid name-value pair in ReplaceCsrEntry.");
                throw new ArgumentException("Invalid name-value pair.");
            }

            string pattern = @$"\bCSR\|{nameValuePair[0]}\b";
            string replace = nameValuePair[1];

            _logger.LogDebug($"Replacing CSR entry {nameValuePair[0]} with {nameValuePair[1]}");
            return Regex.Replace(jsonResult, pattern, replace);
        }

        public static string GetFileNameByProductId(Dictionary<string, string> fileDict, string productId)
        {
            if (fileDict == null || string.IsNullOrWhiteSpace(productId))
            {
                throw new ArgumentNullException(nameof(fileDict), "File dictionary or productId cannot be null.");
            }

            foreach (var kvp in fileDict)
            {
                if (kvp.Value == productId)
                {
                    return Path.GetFileName(kvp.Key);
                }
            }

            throw new KeyNotFoundException("Product ID not found in file dictionary.");
        }

        // FlattenErrors Method
        public string FlattenErrors(List<ErrorResponse> errors)
        {
            if (errors == null || !errors.Any())
            {
                _logger.LogError("Errors list is null or empty.");
                throw new ArgumentException("Errors list cannot be null or empty.");
            }

            _logger.LogDebug("Flattening errors into a single string.");
            return string.Join("\n", errors.Select(error => $"Code: {error.Code}, Message: {error.Message}, Field: {error.Field}"));
        }

        // GetEnrollmentResponse Method
        public EnrollmentResult GetEnrollmentResponse(EnrollmentResponse enrollmentResponse, AnyCAPluginCertificate cert)
        {
            if (enrollmentResponse == null)
            {
                _logger.LogError("EnrollmentResponse is null in GetEnrollmentResponse");
                throw new ArgumentNullException(nameof(enrollmentResponse));
            }

            if (enrollmentResponse.RegistrationError != null)
            {
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = "Error occurred when enrolling."
                };
            }

            return new EnrollmentResult
            {
                Status = (int)EndEntityStatus.GENERATED,
                CARequestID = enrollmentResponse.Result?.SerialNumber,
                Certificate = cert?.Certificate,
                StatusMessage = $"Order successfully created with serial number {enrollmentResponse.Result?.SerialNumber}."
            };
        }

        // GetRenewResponse Method
        public EnrollmentResult GetRenewResponse(EnrollmentResponse renewResponse, AnyCAPluginCertificate cert)
        {
            if (renewResponse == null)
            {
                _logger.LogError("RenewResponse is null in GetRenewResponse");
                throw new ArgumentNullException(nameof(renewResponse));
            }

            if (renewResponse.RegistrationError != null)
            {
                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.FAILED,
                    StatusMessage = "Error occurred when renewing the certificate."
                };
            }

            return new EnrollmentResult
            {
                Status = (int)PKIConstants.Microsoft.RequestDisposition.ISSUED,
                CARequestID = renewResponse.Result?.SerialNumber,
                Certificate = cert?.Certificate,
                StatusMessage = $"Certificate renewal successful with serial number {renewResponse.Result?.SerialNumber}."
            };
        }
    }
}
