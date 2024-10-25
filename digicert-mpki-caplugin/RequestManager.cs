// Copyright 2023 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// thespecific language governing permissions and limitations under the       
// License. 
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Keyfactor.AnyGateway.DigicertMpki.Client.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Linq;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI;
using Microsoft.Extensions.Logging;
using DigicertMpkiSoap;
using Keyfactor.Extensions.CAPlugin.DigicertMpki;
using Keyfactor.PKI.Enums.EJBCA;
using Keyfactor.Logging;
using Keyfactor.Extensions.CAPlugin.DigicertMpki.Models;

namespace Keyfactor.AnyGateway.DigicertMpki
{
    public class RequestManager
    {

        public enum KeyfactorRevokeReasons : uint
        {
            KeyCompromised = 1,
            AffiliationChanged = 3,
            Superseded = 4,
            CessationOfOperation = 5
        }

        public string DnsConstantName { get; set; }
        public string UpnConstantName { get; set; }
        public string IpConstantName { get; set; }
        public string EmailConstantName { get; set; }
        public int OuStartPoint { get; set; }
        private readonly ILogger _logger;
        private readonly DigicertMpkiConfig _config;
        public static Func<string, string> Pemify = ss =>
            ss.Length <= 64 ? ss : ss.Substring(0, 64) + "\n" + Pemify(ss.Substring(64));

        public RequestManager(ILogger logger, DigicertMpkiConfig config)
        { 
            _logger = logger; 
            _config = config;
        }


        public int MapReturnStatus(string digiCertStatus)
        {
            try
            {
                _logger.LogDebug("Entering MapReturnStatus(string digiCertStatus) Method...");
                _logger.LogTrace($"digiCertStatus is {digiCertStatus}");
                int returnStatus;

                switch (digiCertStatus)
                {
                    case "VALID":
                        returnStatus = (int)EndEntityStatus.GENERATED;
                        break;
                    case "Initial":
                    case "PENDING":
                        returnStatus = (int)EndEntityStatus.INPROCESS;
                        break;
                    case "REVOKED":
                        returnStatus = (int)EndEntityStatus.REVOKED;
                        break;
                    default:
                        returnStatus = (int)EndEntityStatus.NEW;
                        break;
                }
                _logger.LogTrace($"returnStatus is {returnStatus}");
                _logger.LogDebug("Exiting MapReturnStatus(string digiCertStatus) Method...");
                return Convert.ToInt32(returnStatus);
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in MapReturnStatus(string digiCertStatus): {e.Message}");
                throw;
            }
        }

        public int MapReturnStatus(CertificateStatusEnum digiCertStatus)
        {
            try
            {
                _logger.LogDebug("Entering MapReturnStatus(string digiCertStatus) Method...");
                _logger.LogTrace($"digiCertStatus is {digiCertStatus}");

                _logger.LogDebug($"Mapping DigiCert status enum: {digiCertStatus}");

                return digiCertStatus switch
                {
                    CertificateStatusEnum.VALID or CertificateStatusEnum.EXPIRED => (int)EndEntityStatus.GENERATED,
                    CertificateStatusEnum.SUSPENDED or CertificateStatusEnum.REVOKED => (int)EndEntityStatus.REVOKED,
                    _ => (int)EndEntityStatus.FAILED,
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in MapReturnStatus(string digiCertStatus): {e.Message}");
                throw;
            }
        }

        public RevokeRequest GetRevokeRequest(uint kfRevokeReason)
        {
            try
            {
                _logger.LogDebug("Entering GetRevokeRequest(uint kfRevokeReason) Method...");
                _logger.LogTrace($"kfRevokeReason is {kfRevokeReason}");
                var req = new RevokeRequest { RevocationReason = MapRevokeReason(kfRevokeReason) };
                _logger.LogTrace($"Revoke Request JSON {JsonConvert.SerializeObject(req)}");
                _logger.LogDebug("Exiting GetRevokeRequest(uint kfRevokeReason) Method...");
                return req;
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in GetRevokeRequest(uint kfRevokeReason): {e.Message}");
                throw;
            }
        }


        public string MapRevokeReason(uint kfRevokeReason)
        {
            try
            {
                _logger.LogDebug("Entering MapRevokeReason(uint kfRevokeReason) Method...");
                _logger.LogTrace($"kfRevokeReason is {kfRevokeReason}");
                _logger.LogDebug("Exiting MapRevokeReason(uint kfRevokeReason) Method...");
                switch (kfRevokeReason)
                {
                    case (uint)KeyfactorRevokeReasons.KeyCompromised:
                        return DigiCertRevokeReasons.KeyCompromise;
                    case (uint)KeyfactorRevokeReasons.CessationOfOperation:
                        return DigiCertRevokeReasons.CessationOfOperation;
                    case (uint)KeyfactorRevokeReasons.AffiliationChanged:
                        return DigiCertRevokeReasons.AffiliationChanged;
                    case (uint)KeyfactorRevokeReasons.Superseded:
                        return DigiCertRevokeReasons.Superseded;
                }

                return "";
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in MapRevokeReason(uint kfRevokeReason): {e.Message}");
                throw;
            }
        }

        internal int MapSoapRevokeReason(RevokeReasonCodeEnum revokeReason)
        {
            try
            {
                _logger.LogDebug("Entering MapRevokeReason(uint kfRevokeReason) Method...");
                _logger.LogTrace($"dcRevokeReason is {revokeReason}");
                _logger.LogDebug("Exiting MapRevokeReason(uint kfRevokeReason) Method...");
                return revokeReason switch
                {
                    RevokeReasonCodeEnum.KeyCompromise => (int)KeyfactorRevokeReasons.KeyCompromised,
                    RevokeReasonCodeEnum.CessationOfOperation => (int)KeyfactorRevokeReasons.CessationOfOperation,
                    RevokeReasonCodeEnum.AffiliationChanged => (int)KeyfactorRevokeReasons.AffiliationChanged,
                    RevokeReasonCodeEnum.Superseded => (int)KeyfactorRevokeReasons.Superseded,
                    _ => throw new ArgumentOutOfRangeException(nameof(revokeReason), "Invalid SOAP revoke reason"),
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in MapRevokeReason(uint kfRevokeReason): {e.Message}");
                throw;
            }
        }

        public int GetRevokeResult(RevokeResponse revokeResponse)
        {
            try
            {
                _logger.LogDebug("Entering GetRevokeResult(IRevokeResponse revokeResponse) Method...");
                if (revokeResponse.RegistrationError != null)
                    return Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.FAILED);
                _logger.LogDebug("Exiting GetRevokeResult(IRevokeResponse revokeResponse) Method...");
                return Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.REVOKED);
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in GetRevokeResult(IRevokeResponse revokeResponse): {e.Message}");
                throw;
            }
        }

        public searchCertificateRequest GetSearchCertificatesRequest(int pageCounter, string templateId)
        {
            try
            {
                _logger.MethodEntry();
                if (string.IsNullOrWhiteSpace(templateId))
                {
                    _logger.LogError("Template ID is null or empty in GetSearchCertificatesRequest");
                    throw new ArgumentException("Template ID cannot be null or empty");
                }
                _logger.LogDebug("Exiting GetSearchCertificatesRequest(int pageCounter, string templateId) Method...");
                _logger.LogTrace($"pageCounter: {pageCounter} TemplateId: {templateId}");
                var requestType = new SearchCertificateRequestType();
                var request = new searchCertificateRequest(requestType);
                request.searchCertificateRequest1.profileOID = templateId;
                request.searchCertificateRequest1.startIndex = pageCounter;
                request.searchCertificateRequest1.startIndexSpecified = true;
                request.searchCertificateRequest1.version = "1.0";
                return request;
            }
            catch (Exception e)
            {
                _logger.LogError($"Exception Occurred in GetSearchCertificatesRequest(int pageCounter, string seatId): {e.Message}");
                throw;
            }
        }

        private (Dictionary<string, string> DNSOut, Dictionary<string, string> MultiOut) ProcessSansArray(
             string[] sanArray, string commonName)
        {
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
                    throw new InvalidOperationException("Error: Single item does not match CommonName.");
                }
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(commonName))
                {
                    if (!sanArray.Contains(commonName))
                    {
                        throw new InvalidOperationException("Error: Multiple items, none of them match CommonName.");
                    }
                    else
                    {
                        dnsOut.Add(commonName, commonName);
                        multiOut = sanArray.Where(item => item != commonName)
                            .ToDictionary(item => item, item => item);
                    }
                }
                else
                {
                    dnsOut.Add(sanArray.First(), sanArray.First());
                    multiOut = sanArray.Skip(1).ToDictionary(item => item, item => item);
                }
            }

            return (dnsOut, multiOut);
        }

        public EnrollmentRequest GetEnrollmentRequest(EnrollmentProductInfo productInfo, string csr,
            Dictionary<string, string[]> san, Dictionary<string, string> productList,Dictionary<Tuple<string,string>,string> sanAttributes,List<CertificateProfile> profiles)
        {
            try
            {
                _logger.LogDebug("Entering GetEnrollmentRequest(EnrollmentProductInfo productInfo, string csr,Dictionary<string, string[]> san) Method...");
                _logger.LogTrace($"csr: {csr}");
                var pemCert = csr;

                var sn = new DigicertSan();
                CertificationRequestInfo csrParsed;

               
                using (TextReader sr = new StringReader(pemCert))
                {
                    var reader = new PemReader(sr);
                    var cReq = reader.ReadObject() as Pkcs10CertificationRequest;
                    csrParsed = cReq?.GetCertificationRequestInfo();
                }
                _logger.LogTrace($"Parsed CSR Subject Value Is: {csrParsed?.Subject.ToString().Split(',')}");

                _logger.LogTrace("Getting File Execution Location to retrieve path");
                var path = GetExecutingPath();
                _logger.LogTrace($"Executing path for the file is: {path}");

                _logger.LogTrace($"Reading in JSON template to parse file {productInfo.ProductID}");
                string templateFileName = GetFileNameByProductId(productList, productInfo.ProductID);
                string jsonTemplate = File.ReadAllText(Path.Combine(GetExecutingPath(), templateFileName));
                var jsonResult = jsonTemplate.ToString();
                _logger.LogTrace($"Read in JSON, resulting template: {jsonResult}");

                //1. Loop through list of Product Parameters and replace in JSON
                foreach (var productParam in productInfo.ProductParameters)
                {
                    jsonResult = ReplaceProductParam(productParam, jsonResult);
                }
                //Clean up the Numeric values remove double quotes
                jsonResult = jsonResult.Replace("\"Numeric|", "");
                jsonResult = jsonResult.Replace("|Numeric\"", "");
                _logger.LogTrace($"Replaced product params, result: {jsonResult}");

                //2. Loop though list of Parsed CSR Elements and replace in JSON
                var csrValues = csrParsed?.Subject.ToString().Split(',');

                bool getCommonNameFromSubject = csrValues != null && csrValues[0].Length > 0;

                //certBot workflow, common name always comes only through SAN and is not in common name
                if (csrValues != null && getCommonNameFromSubject)
                    foreach (var csrValue in csrValues)
                    {
                        var nmValPair = csrValue.Split('=');
                        jsonResult = ReplaceCsrEntry(nmValPair, jsonResult);
                    }

                _logger.LogTrace($"Replaced CSR elements, result: {jsonResult}");

                //3. Replace the RAW CSR content
                jsonResult = jsonResult.Replace("CSR|RAW", csr);

                _logger.LogTrace($"Replaced RAW CSR String, result: {jsonResult}");

                //4. Deserialize Back to EnrollmentRequest
                var enrollmentRequest = JsonConvert.DeserializeObject<EnrollmentRequest>(jsonResult);

                _logger.LogTrace($"Enrollment Serialized JSON before DNS and OU, result: {JsonConvert.SerializeObject(enrollmentRequest)}");

                Dictionary<string, string> MultiOut = null;

                List<DnsName> dnsList = new List<DnsName>();

                //5. If it contains the dns and it is not multi domain get the DNS
                if (san.ContainsKey("dnsname"))
                {
                    var dnsKp = san["dnsname"];
                    _logger.LogTrace($"dnsKP: {dnsKp}");

                    (Dictionary<string, string> DNSOut, Dictionary<string, string> MultiOut) result;

                    if (!getCommonNameFromSubject)
                    {
                        //Cert Bot flow, Cert Bot has no common name and the dns comes from the SAN blank for common name returns first DNS
                        result = ProcessSansArray(dnsKp, "");
                    }
                    else
                    {
                        result = ProcessSansArray(dnsKp, enrollmentRequest?.Attributes?.CommonName);
                    }

                    DnsName up = new DnsName { Id = sanAttributes[Tuple.Create(productInfo.ProductID, "dns_name")], Value = result.DNSOut.FirstOrDefault().Value };

                    MultiOut = result.MultiOut;
                    var jsonResultDns = JsonConvert.SerializeObject(enrollmentRequest);

                    if (!getCommonNameFromSubject)
                        jsonResultDns = ReplaceCsrEntry(new[] { "CN", result.DNSOut.FirstOrDefault().Value }, jsonResult);

                    enrollmentRequest = JsonConvert.DeserializeObject<EnrollmentRequest>(jsonResultDns);
                    dnsList.Add(up);

                    //5. Handle the multiple domain scenario domains go in a different attribute
                    if (MultiOut?.Count > 0)
                    {
                        DnsName mdns = new DnsName { Id = sanAttributes[Tuple.Create(productInfo.ProductID, "dns_name_multi")], Value = string.Join(",", MultiOut.Values) };
                        dnsList.Add(mdns);
                    }

                    sn.DnsName = dnsList;
                }

                //6. Loop through User Principal Entries
                if (san.ContainsKey("upn"))
                {
                    var upList = new List<UserPrincipalName>();
                    var upKp = san["upn"];

                    _logger.LogTrace($"upn: {upKp}");

                    //Multiple UPNs not supported by Digicert so take the first one in the list
                    UserPrincipalName up = new UserPrincipalName { Id = sanAttributes[Tuple.Create(productInfo.ProductID, "user_principal_name")], Value = upKp.FirstOrDefault() };
                    upList.Add(up);
                    sn.UserPrincipalName = upList;
                }

                //7. Loop through IP Entries
                if (san.ContainsKey("ipaddress"))
                {
                    var ipList = new List<IpAddress>();

                    var ipKp = san["ipaddress"];
                    _logger.LogTrace($"ip: {ipKp}");

                    //Multiple IP Addresses not supported by Digicert so take the first one in the list
                    IpAddress ip = new IpAddress { Id = sanAttributes[Tuple.Create(productInfo.ProductID, "ip_address")], Value = ipKp.FirstOrDefault() };
                    ipList.Add(ip);
                    sn.IpAddress = ipList;
                }

                //8. Loop through mail Entries
                if (san.ContainsKey("rfc822name"))
                {
                    var mailList = new List<Rfc822Name>();
                    var mailKp = san["rfc822name"];

                    _logger.LogTrace($"mail: {mailKp}");

                    //Multiple IP Addresses not supported by Digicert so take the first one in the list
                    Rfc822Name mail = new Rfc822Name { Id = sanAttributes[Tuple.Create(productInfo.ProductID, "rfc822_name")], Value = mailKp.FirstOrDefault() };
                    mailList.Add(mail);
                    sn.Rfc822Name = mailList;
                }

                //9. Loop through OUs and replace in Object
                var organizationUnitsRaw = GetValueFromCsr("OU", csrParsed);
                _logger.LogTrace($"Raw Organizational Units: {organizationUnitsRaw}");
                var organizationalUnits = organizationUnitsRaw.Split('/');
                var orgUnits = new List<OrganizationUnit>();
                _logger.LogTrace($"OuStartPoint is {OuStartPoint}");

                var orgUnitIds = ProcessProfiles(profiles, productInfo.ProductID);

                List<string> uniqueCertOrgUnits = new List<string>();

                foreach (var item in orgUnitIds.Item1)
                {
                    // Extract the cert_org_unit part from the key
                    string certOrgUnitKey = item.Key.Item2;
                    uniqueCertOrgUnits.Add(certOrgUnitKey);
                }

                if (uniqueCertOrgUnits.Count > 0)
                {
                    var i = 0;
                    foreach (var ou in organizationalUnits)
                    {
                        var organizationUnit = new OrganizationUnit { Id = uniqueCertOrgUnits[i], Value = ou };
                        orgUnits.Add(organizationUnit);
                        i++;
                    }
                }
                var attributes = enrollmentRequest.Attributes;
                attributes.OrganizationUnit = orgUnits;
                attributes.San = sn;
                enrollmentRequest.Attributes = attributes;
                _logger.LogTrace($"Final enrollmentRequest: {JsonConvert.SerializeObject(enrollmentRequest)}");
                _logger.LogDebug("Exiting GetEnrollmentRequest(EnrollmentProductInfo productInfo, string csr,Dictionary<string, string[]> san) Method...");
                return enrollmentRequest;
            }
            catch (Exception e)
            {
                _logger.LogError($"Error In GetEnrollmentRequest(EnrollmentProductInfo productInfo, string csr,Dictionary<string, string[]> san) : {e.Message}");
                throw;
            }

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

        private static string GetExecutingPath()
        {
            string codeBase = Assembly.GetExecutingAssembly().Location;
            UriBuilder uri = new UriBuilder(codeBase);
            return Path.GetDirectoryName(Uri.UnescapeDataString(uri.Path)) + "\\";
        }

        public EnrollmentResult
            GetEnrollmentResult(
                EnrollmentResponse enrollmentResponse, AnyCAPluginCertificate cert)
        {
            try
            {
                _logger.LogDebug("Entering/Exiting GetEnrollmentResult(IEnrollmentResponse enrollmentResponse) Method...");
                if (enrollmentResponse.RegistrationError != null)
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED, //failure
                        StatusMessage = "Error occurred when enrolling"
                    };

                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.GENERATED, //success
                    CARequestID = enrollmentResponse?.Result?.SerialNumber,
                    Certificate = cert?.Certificate,
                    StatusMessage =
                        $"Order Successfully Created With Order Number {enrollmentResponse.Result.SerialNumber}"
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in GetEnrollmentResult(IEnrollmentResponse enrollmentResponse) Method: {e.Message}");
                throw;
            }
        }

        internal string FlattenErrors(List<ErrorResponse> errors)
        {
            try
            {
                _logger.LogDebug("Entering in FlattenErrors(List<ErrorResponse> errors) Method...");
                var errorMessage = string.Empty;
                foreach (var error in errors) errorMessage += "Code: " + error.Code + " Message: " + error.Message + "Field Name: " + error.Field + "\n";
                _logger.LogDebug("Exiting in FlattenErrors(List<ErrorResponse> errors) Method...");
                return errorMessage;
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in FlattenErrors(List<ErrorResponse> errors) Method: {e.Message}");
                throw;
            }
        }

        internal EnrollmentResult GetRenewResponse(EnrollmentResponse renewResponse, AnyCAPluginCertificate cert)
        {
            try
            {
                _logger.LogDebug("Entering/Exiting in GetRenewResponse(EnrollmentResponse renewResponse) Method...");
                if (renewResponse.RegistrationError != null)
                    return new EnrollmentResult
                    {
                        Status = (int)EndEntityStatus.FAILED, //failure
                        StatusMessage = "Error occurred when enrolling"
                    };

                return new EnrollmentResult
                {
                    Status = (int)EndEntityStatus.GENERATED, //success
                    CARequestID = renewResponse.Result.SerialNumber,
                    Certificate = cert.Certificate,
                    StatusMessage =
                        $"Order Successfully Created With Order Number {renewResponse.Result.SerialNumber}"
                };
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in GetRenewResponse(EnrollmentResponse renewResponse) Method: {e.Message}");
                throw;
            }
        }

        public string GetValueFromCsr(string subjectItem, CertificationRequestInfo csr)
        {
            try
            {
                _logger.LogDebug("Entering in GetValueFromCsr(string subjectItem, CertificationRequestInfo csr) Method...");
                var csrValues = csr.Subject.ToString().Split(',');
                foreach (var val in csrValues)
                {
                    var nmValPair = val.Split('=');
                    _logger.LogTrace($"nmValPair {nmValPair}");
                    if (subjectItem == nmValPair[0]) return nmValPair[1];
                }
                _logger.LogDebug("Exiting in GetValueFromCsr(string subjectItem, CertificationRequestInfo csr) Method...");
                return "";
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in GetValueFromCsr(string subjectItem, CertificationRequestInfo csr) Method: {e.Message}");
                throw;
            }
        }

        private static (Dictionary<Tuple<string, string>, string>, Dictionary<Tuple<string, string>, bool>) ProcessProfiles(List<CertificateProfile> certificateProfiles, string profileId)
        {
            // Dictionary to store the result
            Dictionary<Tuple<string, string>, string> subjectAttributeIds = new Dictionary<Tuple<string, string>, string>();
            Dictionary<Tuple<string, string>, bool> mandatoryFlags = new Dictionary<Tuple<string, string>, bool>();

            // Filter the list by profileId
            var filteredProfiles = certificateProfiles.FindAll(profile => profile.Id == profileId);

            // Iterate over each filtered CertificateProfile
            foreach (var profile in filteredProfiles)
            {
                string certificateId = profile.Id;

                // Check if the certificate has subject attributes
                if (profile.Certificate != null && profile.Certificate.Subject != null && profile.Certificate.Subject.Attributes != null)
                {
                    foreach (var attribute in profile.Certificate.Subject.Attributes)
                    {
                        // Only process attributes that have an ID
                        if (!string.IsNullOrEmpty(attribute.Id))
                        {
                            // Create a tuple with the certificate ID and the subject attribute ID
                            var key = new Tuple<string, string>(certificateId, attribute.Id);

                            // Store the attribute type in the dictionary
                            subjectAttributeIds[key] = attribute.Type;

                            // Store the mandatory flag in the separate dictionary
                            mandatoryFlags[key] = attribute.Mandatory;
                        }
                    }
                }
            }

            // Return both dictionaries as a tuple
            return (subjectAttributeIds, mandatoryFlags);
        }


        private string ReplaceProductParam(KeyValuePair<string, string> productParam, string jsonResult)
        {
            try
            {
                _logger.LogDebug("Entering ReplaceProductParam(KeyValuePair<string, string> productParam, string jsonResult) Method...");
                return jsonResult.Replace("EnrollmentParam|" + productParam.Key, productParam.Value);
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in ReplaceProductParam(KeyValuePair<string, string> productParam, string jsonResult) Method: {e.Message}");
                throw;
            }
        }

        private string ReplaceCsrEntry(string[] nameValuePair, string jsonResult)
        {
            try
            {
                _logger.LogDebug("Entering in ReplaceCsrEntry(string[] nameValuePair, string jsonResult) Method...");
                string pattern = @"\b" + "CSR\\|" + nameValuePair[0] + @"\b";
                string replace = nameValuePair[1];
                _logger.LogTrace($"replace {replace}");
                _logger.LogDebug("Exiting in ReplaceCsrEntry(string[] nameValuePair, string jsonResult) Method...");
                return Regex.Replace(jsonResult, pattern, replace);
            }
            catch (Exception e)
            {
                _logger.LogError($"Error in ReplaceCsrEntry(string[] nameValuePair, string jsonResult) Method: {e.Message}");
                throw;
            }
        }
    }
}