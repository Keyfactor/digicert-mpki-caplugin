using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keyfactor.Extensions.CAPlugin.DigicertMpki;
using Xunit;

namespace DigicertMpkiCaplugin.Tests
{
    /// <summary>
    /// Unit tests for container deployment features including environment variable support,
    /// cross-platform path handling, and base64 certificate loading.
    /// </summary>
    public class ContainerDeploymentTests : IDisposable
    {
        private readonly List<string> _envVarsToCleanup = new();

        public void Dispose()
        {
            // Clean up any environment variables set during tests
            foreach (var envVar in _envVarsToCleanup)
            {
                Environment.SetEnvironmentVariable(envVar, null);
            }
        }

        private void SetEnvironmentVariable(string name, string? value)
        {
            Environment.SetEnvironmentVariable(name, value);
            _envVarsToCleanup.Add(name);
        }

        #region Environment Variable Tests

        [Fact]
        public void Constants_EnvironmentVariableNames_AreCorrect()
        {
            // Verify environment variable names match expected values
            Assert.Equal("DIGICERT_API_KEY", Constants.EnvApiKey);
            Assert.Equal("DIGICERT_CLIENT_CERT_PASSWORD", Constants.EnvClientCertPassword);
            Assert.Equal("DIGICERT_CLIENT_CERT_BASE64", Constants.EnvClientCertBase64);
        }

        [Fact]
        public void Constants_TemplateDirectory_IsConfigurable()
        {
            // Verify TemplateDirectory constant exists
            Assert.Equal("TemplateDirectory", Constants.TemplateDirectory);
        }

        #endregion

        #region Configuration Tests

        [Fact]
        public void DigicertMpkiConfig_HasTemplateDirectoryProperty()
        {
            // Verify the config class has the TemplateDirectory property
            var config = new DigicertMpkiConfig();

            Assert.Null(config.TemplateDirectory); // Default should be null

            config.TemplateDirectory = "/app/templates";
            Assert.Equal("/app/templates", config.TemplateDirectory);
        }

        [Fact]
        public void DigicertMpkiConfig_SupportsLinuxPaths()
        {
            var config = new DigicertMpkiConfig
            {
                TemplateDirectory = "/app/templates",
                ClientCertLocation = "/secrets/client.pfx"
            };

            Assert.Equal("/app/templates", config.TemplateDirectory);
            Assert.Equal("/secrets/client.pfx", config.ClientCertLocation);
        }

        [Fact]
        public void DigicertMpkiConfig_SupportsWindowsPaths()
        {
            var config = new DigicertMpkiConfig
            {
                TemplateDirectory = @"C:\templates",
                ClientCertLocation = @"C:\secrets\client.pfx"
            };

            Assert.Equal(@"C:\templates", config.TemplateDirectory);
            Assert.Equal(@"C:\secrets\client.pfx", config.ClientCertLocation);
        }

        #endregion

        #region Path Handling Tests

        [Fact]
        public void PathDirectorySeparatorChar_IsOsAppropriate()
        {
            // This test verifies that Path.DirectorySeparatorChar is being used correctly
            // On Windows it should be '\', on Linux it should be '/'
            char separator = Path.DirectorySeparatorChar;

            if (OperatingSystem.IsWindows())
            {
                Assert.Equal('\\', separator);
            }
            else
            {
                Assert.Equal('/', separator);
            }
        }

        [Fact]
        public void PathCombine_HandlesLinuxPaths()
        {
            string basePath = "/app";
            string relativePath = "templates";

            string combined = Path.Combine(basePath, relativePath);

            // Path.Combine should work correctly regardless of OS
            Assert.Contains("templates", combined);
            Assert.StartsWith("/app", combined);
        }

        [Fact]
        public void PathIsPathRooted_DetectsLinuxAbsolutePaths()
        {
            Assert.True(Path.IsPathRooted("/app/templates"));
            Assert.True(Path.IsPathRooted("/secrets/client.pfx"));
        }

        [Fact]
        public void PathIsPathRooted_DetectsWindowsAbsolutePaths()
        {
            Assert.True(Path.IsPathRooted(@"C:\templates"));
            Assert.True(Path.IsPathRooted(@"C:\secrets\client.pfx"));
        }

        [Fact]
        public void PathIsPathRooted_DetectsRelativePaths()
        {
            Assert.False(Path.IsPathRooted("templates"));
            Assert.False(Path.IsPathRooted("./templates"));
            Assert.False(Path.IsPathRooted("../templates"));
        }

        #endregion

        #region Base64 Certificate Tests

        [Fact]
        public void Base64Encoding_RoundTrip_PreservesData()
        {
            // Test that base64 encoding/decoding works correctly for binary data
            byte[] originalData = new byte[256];
            new Random(42).NextBytes(originalData);

            string base64 = Convert.ToBase64String(originalData);
            byte[] decodedData = Convert.FromBase64String(base64);

            Assert.Equal(originalData, decodedData);
        }

        [Fact]
        public void Base64Decoding_InvalidInput_ThrowsFormatException()
        {
            string invalidBase64 = "not-valid-base64!!!";

            Assert.Throws<FormatException>(() => Convert.FromBase64String(invalidBase64));
        }

        [Fact]
        public void X509Certificate2_CanBeCreatedFromBytes()
        {
            // Create a self-signed certificate for testing
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=TestCert",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var certificate = request.CreateSelfSigned(
                DateTimeOffset.Now,
                DateTimeOffset.Now.AddDays(1));

            // Export to PFX bytes
            string password = "test-password";
            byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

            // Verify we can create certificate from bytes (simulates base64 flow)
            string base64 = Convert.ToBase64String(pfxBytes);
            byte[] decodedBytes = Convert.FromBase64String(base64);

            using var loadedCert = new X509Certificate2(decodedBytes, password);
            Assert.Equal("CN=TestCert", loadedCert.Subject);
        }

        #endregion

        #region Environment Variable Fallback Tests

        [Fact]
        public void EnvironmentVariable_CanBeReadCorrectly()
        {
            string testValue = "test-api-key-12345";
            SetEnvironmentVariable(Constants.EnvApiKey, testValue);

            string? retrieved = Environment.GetEnvironmentVariable(Constants.EnvApiKey);

            Assert.Equal(testValue, retrieved);
        }

        [Fact]
        public void EnvironmentVariable_ReturnsNullWhenNotSet()
        {
            // Ensure the variable is not set
            Environment.SetEnvironmentVariable("NONEXISTENT_VAR_12345", null);

            string? retrieved = Environment.GetEnvironmentVariable("NONEXISTENT_VAR_12345");

            Assert.Null(retrieved);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void StringIsNullOrEmpty_DetectsEmptyValues(string? value)
        {
            // Verify our empty-checking logic works correctly
            Assert.True(string.IsNullOrEmpty(value) || string.IsNullOrWhiteSpace(value));
        }

        #endregion

        #region Template Directory Tests

        [Fact]
        public void Directory_Exists_WorksWithAbsolutePaths()
        {
            // Get a directory that should exist
            string tempPath = Path.GetTempPath();

            Assert.True(Directory.Exists(tempPath));
        }

        [Fact]
        public void Directory_Exists_ReturnsFalseForNonexistent()
        {
            string fakePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

            Assert.False(Directory.Exists(fakePath));
        }

        [Fact]
        public void GetDirectoryName_WorksWithLinuxPaths()
        {
            string path = "/app/extensions/plugin.dll";
            string? directory = Path.GetDirectoryName(path);

            Assert.NotNull(directory);
            Assert.Contains("extensions", directory);
        }

        [Fact]
        public void GetDirectoryName_WorksWithWindowsPaths()
        {
            string path = @"C:\Program Files\Keyfactor\plugin.dll";
            string? directory = Path.GetDirectoryName(path);

            Assert.NotNull(directory);
            Assert.Contains("Keyfactor", directory);
        }

        #endregion

        #region TemplatesJson Configuration Tests

        [Fact]
        public void Constants_TemplatesJson_IsConfigurable()
        {
            Assert.Equal("TemplatesJson", Constants.TemplatesJson);
        }

        [Fact]
        public void DigicertMpkiConfig_HasTemplatesJsonProperty()
        {
            var config = new DigicertMpkiConfig();

            Assert.Null(config.TemplatesJson); // Default should be null

            config.TemplatesJson = "[{}]";
            Assert.Equal("[{}]", config.TemplatesJson);
        }

        [Fact]
        public void DigicertMpkiConfig_TemplatesJsonCanHoldLargeValue()
        {
            var config = new DigicertMpkiConfig();

            // Simulate a realistic JSON array with multiple templates
            string largeJson = @"[
                {""profile"":{""id"":""2.16.840.1.101.2.1.11.39""},""csr"":""CSR|RAW"",""validity"":{""years"":1}},
                {""profile"":{""id"":""2.16.840.1.101.2.1.11.40""},""csr"":""CSR|RAW"",""validity"":{""years"":2}},
                {""profile"":{""id"":""2.16.840.1.101.2.1.11.41""},""csr"":""CSR|RAW"",""validity"":{""years"":3}}
            ]";

            config.TemplatesJson = largeJson;
            Assert.Equal(largeJson, config.TemplatesJson);
        }

        #endregion

        #region TemplateProvider Tests

        [Fact]
        public void TemplateProvider_HasJsonTemplates_ReturnsTrueWhenJsonConfigured()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[{""profile"":{""id"":""test""}}]"
            };

            var provider = new TemplateProvider(config, null);

            Assert.True(provider.HasJsonTemplates);
        }

        [Fact]
        public void TemplateProvider_HasJsonTemplates_ReturnsFalseWhenNotConfigured()
        {
            var config = new DigicertMpkiConfig();
            var provider = new TemplateProvider(config, null);

            Assert.False(provider.HasJsonTemplates);
        }

        [Fact]
        public void TemplateProvider_HasJsonTemplates_ReturnsFalseForEmptyString()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = ""
            };

            var provider = new TemplateProvider(config, null);

            Assert.False(provider.HasJsonTemplates);
        }

        [Fact]
        public void TemplateProvider_GetProfileIds_ReturnsProfileIdsFromJsonConfig()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {""profile"":{""id"":""2.16.840.1.101.2.1.11.39""},""csr"":""CSR|RAW""},
                    {""profile"":{""id"":""2.16.840.1.101.2.1.11.40""},""csr"":""CSR|RAW""}
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var profileIds = provider.GetProfileIds();

            Assert.Equal(2, profileIds.Count);
            Assert.Contains("2.16.840.1.101.2.1.11.39", profileIds.Values);
            Assert.Contains("2.16.840.1.101.2.1.11.40", profileIds.Values);
        }

        [Fact]
        public void TemplateProvider_GetProfileIdList_ReturnsListOfIds()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {""profile"":{""id"":""profile1""}},
                    {""profile"":{""id"":""profile2""}},
                    {""profile"":{""id"":""profile3""}}
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var profileList = provider.GetProfileIdList();

            Assert.Equal(3, profileList.Count);
            Assert.Contains("profile1", profileList);
            Assert.Contains("profile2", profileList);
            Assert.Contains("profile3", profileList);
        }

        [Fact]
        public void TemplateProvider_GetTemplateByProfileId_ReturnsCorrectTemplate()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {""profile"":{""id"":""profile1""},""validity"":{""years"":1}},
                    {""profile"":{""id"":""profile2""},""validity"":{""years"":2}}
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var template = provider.GetTemplateByProfileId("profile1");

            Assert.Contains("profile1", template);
            Assert.Contains("\"years\": 1", template);
        }

        [Fact]
        public void TemplateProvider_GetTemplateByProfileId_ThrowsForUnknownProfile()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[{""profile"":{""id"":""profile1""}}]"
            };

            var provider = new TemplateProvider(config, null);

            Assert.Throws<KeyNotFoundException>(() => provider.GetTemplateByProfileId("unknown-profile"));
        }

        [Fact]
        public void TemplateProvider_GetEnrollmentParameters_ExtractsParamsFromTemplates()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {
                        ""profile"":{""id"":""profile1""},
                        ""subject"":{
                            ""common_name"":""EnrollmentParam|CommonName"",
                            ""email"":""EnrollmentParam|Email""
                        }
                    }
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var enrollmentParams = provider.GetEnrollmentParameters();

            Assert.Contains("CommonName", enrollmentParams.Keys);
            Assert.Contains("Email", enrollmentParams.Keys);
        }

        [Fact]
        public void TemplateProvider_GetEnrollmentParameters_HandlesNumericParams()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {
                        ""profile"":{""id"":""profile1""},
                        ""validity"":{
                            ""years"":""Numeric|EnrollmentParam|ValidityYears|1""
                        }
                    }
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var enrollmentParams = provider.GetEnrollmentParameters();

            Assert.Contains("ValidityYears", enrollmentParams.Keys);
            Assert.Equal("Number", enrollmentParams["ValidityYears"]);
        }

        [Fact]
        public void TemplateProvider_InvalidJsonConfig_ThrowsOnTemplateLoad()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = "not valid json"
            };

            var provider = new TemplateProvider(config, null);

            // GetProfileIds returns empty (with error logging) for invalid JSON
            var profileIds = provider.GetProfileIds();
            Assert.Empty(profileIds);

            // But GetTemplateByProfileId throws when trying to load/parse the templates
            Assert.Throws<InvalidOperationException>(() => provider.GetTemplateByProfileId("any-id"));
        }

        [Fact]
        public void TemplateProvider_EmptyJsonArray_ReturnsEmptyProfileIds()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = "[]"
            };

            var provider = new TemplateProvider(config, null);
            var profileIds = provider.GetProfileIds();

            Assert.Empty(profileIds);
        }

        [Fact]
        public void TemplateProvider_TemplateWithoutProfileId_IsSkipped()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {""profile"":{""id"":""valid-profile""}},
                    {""notAProfile"":{""something"":""else""}},
                    {""profile"":{""name"":""no-id-field""}}
                ]"
            };

            var provider = new TemplateProvider(config, null);
            var profileIds = provider.GetProfileIds();

            Assert.Single(profileIds);
            Assert.Contains("valid-profile", profileIds.Values);
        }

        [Fact]
        public void TemplateProvider_CachesResults()
        {
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[{""profile"":{""id"":""profile1""}}]"
            };

            var provider = new TemplateProvider(config, null);

            // First call
            var profileIds1 = provider.GetProfileIds();
            // Second call should return same instance (cached)
            var profileIds2 = provider.GetProfileIds();

            Assert.Same(profileIds1, profileIds2);
        }

        [Fact]
        public void TemplateProvider_ComplexTemplate_ParsesCorrectly()
        {
            // This tests with a realistic template structure similar to the user's sample
            var config = new DigicertMpkiConfig
            {
                TemplatesJson = @"[
                    {
                        ""profile"": {
                            ""id"": ""2.16.840.1.101.2.1.11.39""
                        },
                        ""csr"": ""CSR|RAW"",
                        ""attributes"": {
                            ""common_name"": ""CSR|CN"",
                            ""email"": ""EnrollmentParam|Email"",
                            ""dns_names"": [""CSR|SANS:DnsName""]
                        },
                        ""seat"": {
                            ""seat_id"": ""Numeric|EnrollmentParam|SeatId|0""
                        },
                        ""validity"": {
                            ""years"": 1
                        }
                    }
                ]"
            };

            var provider = new TemplateProvider(config, null);

            // Verify profile ID extraction
            var profileIds = provider.GetProfileIds();
            Assert.Single(profileIds);
            Assert.Contains("2.16.840.1.101.2.1.11.39", profileIds.Values);

            // Verify template retrieval
            var template = provider.GetTemplateByProfileId("2.16.840.1.101.2.1.11.39");
            Assert.Contains("CSR|RAW", template);
            Assert.Contains("CSR|CN", template);

            // Verify enrollment parameters extraction
            var enrollmentParams = provider.GetEnrollmentParameters();
            Assert.Contains("Email", enrollmentParams.Keys);
            Assert.Contains("SeatId", enrollmentParams.Keys);
            Assert.Equal("Number", enrollmentParams["SeatId"]);
        }

        #endregion
    }
}
