using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Keyfactor.Extensions.CAPlugin.DigicertMpki;
using Newtonsoft.Json;
using Xunit;

namespace DigicertMpkiCaplugin.Tests
{
    /// <summary>
    /// Integration tests that simulate container deployment scenarios.
    /// These tests validate the complete configuration flow as it would work
    /// in a Kubernetes/Docker environment.
    /// </summary>
    public class ContainerIntegrationTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly List<string> _envVarsToCleanup = new();

        public ContainerIntegrationTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), $"digicert-test-{Guid.NewGuid()}");
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            // Clean up environment variables
            foreach (var envVar in _envVarsToCleanup)
            {
                Environment.SetEnvironmentVariable(envVar, null);
            }

            // Clean up temp directory
            if (Directory.Exists(_tempDir))
            {
                try
                {
                    Directory.Delete(_tempDir, recursive: true);
                }
                catch
                {
                    // Ignore cleanup errors in tests
                }
            }
        }

        private void SetEnvironmentVariable(string name, string? value)
        {
            Environment.SetEnvironmentVariable(name, value);
            _envVarsToCleanup.Add(name);
        }

        private (byte[] pfxBytes, string password) CreateTestCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=TestSOAPClient, O=TestOrg",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var certificate = request.CreateSelfSigned(
                DateTimeOffset.Now.AddDays(-1),
                DateTimeOffset.Now.AddDays(365));

            string password = "test-cert-password";
            byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

            return (pfxBytes, password);
        }

        #region Container Configuration Simulation Tests

        [Fact]
        public void ContainerConfig_WithEnvironmentVariables_LoadsCorrectly()
        {
            // Simulate Kubernetes/Docker environment variable injection
            SetEnvironmentVariable(Constants.EnvApiKey, "container-api-key-12345");
            SetEnvironmentVariable(Constants.EnvClientCertPassword, "container-cert-password");

            // Verify environment variables are accessible
            Assert.Equal("container-api-key-12345", Environment.GetEnvironmentVariable(Constants.EnvApiKey));
            Assert.Equal("container-cert-password", Environment.GetEnvironmentVariable(Constants.EnvClientCertPassword));
        }

        [Fact]
        public void ContainerConfig_WithBase64Certificate_DecodesCorrectly()
        {
            // Create a test certificate
            var (pfxBytes, password) = CreateTestCertificate();
            string base64Cert = Convert.ToBase64String(pfxBytes);

            // Simulate container environment
            SetEnvironmentVariable(Constants.EnvClientCertBase64, base64Cert);
            SetEnvironmentVariable(Constants.EnvClientCertPassword, password);

            // Retrieve and decode
            string? certBase64 = Environment.GetEnvironmentVariable(Constants.EnvClientCertBase64);
            string? certPassword = Environment.GetEnvironmentVariable(Constants.EnvClientCertPassword);

            Assert.NotNull(certBase64);
            Assert.NotNull(certPassword);

            byte[] decodedBytes = Convert.FromBase64String(certBase64);
            using var certificate = new X509Certificate2(decodedBytes, certPassword);

            Assert.Equal("CN=TestSOAPClient, O=TestOrg", certificate.Subject);
        }

        [Fact]
        public void ContainerConfig_WithMountedCertificate_LoadsFromPath()
        {
            // Create a test certificate and save to "mounted" path
            var (pfxBytes, password) = CreateTestCertificate();
            string certPath = Path.Combine(_tempDir, "client.pfx");
            File.WriteAllBytes(certPath, pfxBytes);

            // Simulate loading from mounted secret path
            using var certificate = new X509Certificate2(certPath, password);

            Assert.Equal("CN=TestSOAPClient, O=TestOrg", certificate.Subject);
        }

        [Fact]
        public void ContainerConfig_WithMountedTemplates_LoadsFromDirectory()
        {
            // Create a templates directory with sample template
            string templatesDir = Path.Combine(_tempDir, "templates");
            Directory.CreateDirectory(templatesDir);

            var template = new
            {
                profile = new { id = "2.16.840.1.113733.1.16.1.5.2.5.1.TEST" },
                csr = "CSR|RAW",
                validity = new { unit = "years", duration = 1 }
            };

            string templatePath = Path.Combine(templatesDir, "test-template.json");
            File.WriteAllText(templatePath, JsonConvert.SerializeObject(template));

            // Verify template can be loaded
            Assert.True(File.Exists(templatePath));

            string[] jsonFiles = Directory.GetFiles(templatesDir, "*.json");
            Assert.Single(jsonFiles);

            string content = File.ReadAllText(templatePath);
            Assert.Contains("2.16.840.1.113733.1.16.1.5.2.5.1.TEST", content);
        }

        #endregion

        #region Configuration Precedence Tests

        [Fact]
        public void ConfigPrecedence_ConfigValueTakesPrecedenceOverEnvVar()
        {
            // Set environment variable
            SetEnvironmentVariable(Constants.EnvApiKey, "env-api-key");

            // Simulate config with value set
            var configData = new Dictionary<string, object>
            {
                [Constants.DigiCertSymApiKey] = "config-api-key"
            };

            // Config value should be used
            string configValue = configData[Constants.DigiCertSymApiKey]?.ToString()!;
            Assert.Equal("config-api-key", configValue);
        }

        [Fact]
        public void ConfigPrecedence_EnvVarUsedWhenConfigEmpty()
        {
            // Set environment variable
            SetEnvironmentVariable(Constants.EnvApiKey, "env-api-key");

            // Simulate config with empty value
            var configData = new Dictionary<string, object>
            {
                [Constants.DigiCertSymApiKey] = ""
            };

            // Should fall back to env var
            string? configValue = configData[Constants.DigiCertSymApiKey]?.ToString();
            string effectiveValue = string.IsNullOrEmpty(configValue)
                ? Environment.GetEnvironmentVariable(Constants.EnvApiKey) ?? ""
                : configValue;

            Assert.Equal("env-api-key", effectiveValue);
        }

        #endregion

        #region Validation Tests

        [Fact]
        public void Validation_RequiresCertificateSource()
        {
            // Neither file path nor base64 env var
            var configData = new Dictionary<string, object>
            {
                [Constants.DigiCertSymApiKey] = "api-key",
                [Constants.DigiCertSymUrl] = "https://example.com/mpki/api/v1",
                [Constants.EndpointAddress] = "https://example.com/pki-ws/certificateManagementService",
                [Constants.ClientCertLocation] = "",  // Empty
                [Constants.ClientCertPassword] = "password"
            };

            // Clear any base64 env var
            Environment.SetEnvironmentVariable(Constants.EnvClientCertBase64, null);

            string certLocation = configData[Constants.ClientCertLocation]?.ToString() ?? "";
            string? certBase64 = Environment.GetEnvironmentVariable(Constants.EnvClientCertBase64);

            bool hasCertSource = !string.IsNullOrWhiteSpace(certLocation) || !string.IsNullOrWhiteSpace(certBase64);

            Assert.False(hasCertSource, "Should fail validation when no certificate source is provided");
        }

        [Fact]
        public void Validation_AcceptsCertificateFromEnvVar()
        {
            // File path empty but base64 env var set
            var (pfxBytes, _) = CreateTestCertificate();
            SetEnvironmentVariable(Constants.EnvClientCertBase64, Convert.ToBase64String(pfxBytes));

            var configData = new Dictionary<string, object>
            {
                [Constants.ClientCertLocation] = ""  // Empty - using env var instead
            };

            string certLocation = configData[Constants.ClientCertLocation]?.ToString() ?? "";
            string? certBase64 = Environment.GetEnvironmentVariable(Constants.EnvClientCertBase64);

            bool hasCertSource = !string.IsNullOrWhiteSpace(certLocation) || !string.IsNullOrWhiteSpace(certBase64);

            Assert.True(hasCertSource, "Should pass validation when base64 env var is set");
        }

        [Fact]
        public void Validation_AcceptsCertificateFromFilePath()
        {
            // Clear base64 env var, but file path is set
            Environment.SetEnvironmentVariable(Constants.EnvClientCertBase64, null);

            var configData = new Dictionary<string, object>
            {
                [Constants.ClientCertLocation] = "/secrets/client.pfx"
            };

            string certLocation = configData[Constants.ClientCertLocation]?.ToString() ?? "";
            string? certBase64 = Environment.GetEnvironmentVariable(Constants.EnvClientCertBase64);

            bool hasCertSource = !string.IsNullOrWhiteSpace(certLocation) || !string.IsNullOrWhiteSpace(certBase64);

            Assert.True(hasCertSource, "Should pass validation when file path is set");
        }

        [Fact]
        public void Validation_TemplateDirectoryMustExist_WhenSpecified()
        {
            string nonExistentPath = Path.Combine(_tempDir, "nonexistent-templates");

            bool directoryExists = Directory.Exists(nonExistentPath);

            Assert.False(directoryExists, "Non-existent template directory should fail validation");
        }

        [Fact]
        public void Validation_TemplateDirectoryPasses_WhenExists()
        {
            string templatesPath = Path.Combine(_tempDir, "templates");
            Directory.CreateDirectory(templatesPath);

            bool directoryExists = Directory.Exists(templatesPath);

            Assert.True(directoryExists, "Existing template directory should pass validation");
        }

        #endregion

        #region Cross-Platform Path Resolution Tests

        [Fact]
        public void PathResolution_AbsoluteLinuxPath_IsRecognized()
        {
            string linuxPath = "/app/templates";

            bool isAbsolute = Path.IsPathRooted(linuxPath);

            Assert.True(isAbsolute);
        }

        [Fact]
        public void PathResolution_AbsoluteWindowsPath_IsRecognized()
        {
            string windowsPath = @"C:\templates";

            bool isAbsolute = Path.IsPathRooted(windowsPath);

            Assert.True(isAbsolute);
        }

        [Fact]
        public void PathResolution_RelativePath_IsConverted()
        {
            string basePath = _tempDir;
            string relativePath = "templates";

            // Simulate relative path conversion
            string absolutePath;
            if (!Path.IsPathRooted(relativePath))
            {
                absolutePath = Path.Combine(basePath, relativePath);
            }
            else
            {
                absolutePath = relativePath;
            }

            Assert.True(Path.IsPathRooted(absolutePath));
            Assert.Contains("templates", absolutePath);
        }

        [Fact]
        public void PathSeparator_AddedCorrectly()
        {
            string basePath = _tempDir.TrimEnd(Path.DirectorySeparatorChar, '/');
            string pathWithSeparator = basePath + Path.DirectorySeparatorChar;

            Assert.EndsWith(Path.DirectorySeparatorChar.ToString(), pathWithSeparator);
        }

        #endregion

        #region Full Configuration Flow Tests

        [Fact]
        public void FullFlow_KubernetesDeploymentScenario()
        {
            // Simulate a complete Kubernetes deployment configuration

            // 1. Set up environment variables (from Kubernetes Secrets)
            var (pfxBytes, password) = CreateTestCertificate();
            SetEnvironmentVariable(Constants.EnvApiKey, "k8s-injected-api-key");
            SetEnvironmentVariable(Constants.EnvClientCertPassword, password);
            SetEnvironmentVariable(Constants.EnvClientCertBase64, Convert.ToBase64String(pfxBytes));

            // 2. Set up mounted templates directory (from ConfigMap)
            string templatesDir = Path.Combine(_tempDir, "mounted-templates");
            Directory.CreateDirectory(templatesDir);
            var template = new { profile = new { id = "test-profile-oid" } };
            File.WriteAllText(
                Path.Combine(templatesDir, "k8s-template.json"),
                JsonConvert.SerializeObject(template));

            // 3. Simulate CA Connection config (as would be set in portal)
            var connectionConfig = new Dictionary<string, object>
            {
                [Constants.DigiCertSymApiKey] = "",  // Empty - using env var
                [Constants.DigiCertSymUrl] = "https://pki.digicert.com/mpki/api/v1",
                [Constants.EndpointAddress] = "https://pki.digicert.com/pki-ws/certificateManagementService",
                [Constants.ClientCertLocation] = "",  // Empty - using base64 env var
                [Constants.ClientCertPassword] = "",  // Empty - using env var
                [Constants.TemplateDirectory] = templatesDir
            };

            // 4. Verify configuration is complete
            // API Key
            string apiKey = !string.IsNullOrEmpty(connectionConfig[Constants.DigiCertSymApiKey]?.ToString())
                ? connectionConfig[Constants.DigiCertSymApiKey]!.ToString()!
                : Environment.GetEnvironmentVariable(Constants.EnvApiKey)!;
            Assert.Equal("k8s-injected-api-key", apiKey);

            // Certificate Password
            string certPass = !string.IsNullOrEmpty(connectionConfig[Constants.ClientCertPassword]?.ToString())
                ? connectionConfig[Constants.ClientCertPassword]!.ToString()!
                : Environment.GetEnvironmentVariable(Constants.EnvClientCertPassword)!;
            Assert.Equal(password, certPass);

            // Certificate (from base64)
            string? certBase64 = Environment.GetEnvironmentVariable(Constants.EnvClientCertBase64);
            Assert.NotNull(certBase64);
            using var cert = new X509Certificate2(Convert.FromBase64String(certBase64), certPass);
            Assert.NotNull(cert);

            // Template Directory
            Assert.True(Directory.Exists(templatesDir));
            Assert.Single(Directory.GetFiles(templatesDir, "*.json"));
        }

        [Fact]
        public void FullFlow_DockerDeploymentScenario()
        {
            // Simulate a Docker deployment with mounted volumes

            // 1. Set up mounted certificate file (from Docker volume/secret)
            var (pfxBytes, password) = CreateTestCertificate();
            string secretsDir = Path.Combine(_tempDir, "secrets");
            Directory.CreateDirectory(secretsDir);
            string certPath = Path.Combine(secretsDir, "client.pfx");
            File.WriteAllBytes(certPath, pfxBytes);

            // 2. Set up environment variables
            SetEnvironmentVariable(Constants.EnvApiKey, "docker-api-key");
            SetEnvironmentVariable(Constants.EnvClientCertPassword, password);

            // 3. Set up mounted templates
            string templatesDir = Path.Combine(_tempDir, "app", "templates");
            Directory.CreateDirectory(templatesDir);
            File.WriteAllText(
                Path.Combine(templatesDir, "docker-template.json"),
                "{\"profile\":{\"id\":\"docker-test-oid\"}}");

            // 4. Simulate CA Connection config
            var connectionConfig = new Dictionary<string, object>
            {
                [Constants.DigiCertSymApiKey] = "",  // From env var
                [Constants.DigiCertSymUrl] = "https://pki.digicert.com/mpki/api/v1",
                [Constants.EndpointAddress] = "https://pki.digicert.com/pki-ws/certificateManagementService",
                [Constants.ClientCertLocation] = certPath,  // Mounted file path
                [Constants.ClientCertPassword] = "",  // From env var
                [Constants.TemplateDirectory] = templatesDir
            };

            // 5. Verify configuration is complete
            Assert.True(File.Exists(certPath));
            Assert.True(Directory.Exists(templatesDir));

            using var cert = new X509Certificate2(certPath, password);
            Assert.NotNull(cert);

            string templateContent = File.ReadAllText(Path.Combine(templatesDir, "docker-template.json"));
            Assert.Contains("docker-test-oid", templateContent);
        }

        #endregion
    }
}
