using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Keyfactor.Extensions.CAPlugin.DigicertMpki
{
    /// <summary>
    /// Provides enrollment templates from either JSON configuration or file system.
    /// Supports container deployments where templates can be embedded in config.
    /// </summary>
    public class TemplateProvider
    {
        private readonly DigicertMpkiConfig _config;
        private readonly ILogger _logger;
        private Dictionary<string, string> _templateCache; // profileId -> template JSON
        private Dictionary<string, string> _profileIdCache; // key -> profileId (key is profileId for JSON config, filepath for file-based)

        public TemplateProvider(DigicertMpkiConfig config, ILogger logger)
        {
            _config = config;
            _logger = logger;
        }

        /// <summary>
        /// Determines if templates are configured via JSON config value.
        /// </summary>
        public bool HasJsonTemplates => !string.IsNullOrEmpty(_config?.TemplatesJson);

        /// <summary>
        /// Gets all profile IDs from available templates.
        /// Returns a dictionary mapping a key (profileId for JSON, filepath for files) to the profile ID.
        /// </summary>
        public Dictionary<string, string> GetProfileIds()
        {
            if (_profileIdCache != null)
                return _profileIdCache;

            if (HasJsonTemplates)
            {
                _profileIdCache = ExtractProfileIdsFromJsonConfig();
            }
            else
            {
                string templateDir = GetTemplateDirectory();
                _profileIdCache = ExtractProfileIdsFromDirectory(templateDir);
            }

            return _profileIdCache;
        }

        /// <summary>
        /// Gets the list of profile ID values (OIDs).
        /// </summary>
        public List<string> GetProfileIdList()
        {
            var profileIds = GetProfileIds();
            return new List<string>(profileIds.Values);
        }

        /// <summary>
        /// Gets the template JSON content for a given profile ID.
        /// </summary>
        public string GetTemplateByProfileId(string profileId)
        {
            EnsureTemplatesLoaded();

            if (_templateCache.TryGetValue(profileId, out string template))
            {
                return template;
            }

            throw new KeyNotFoundException($"Template not found for profile ID: {profileId}");
        }

        /// <summary>
        /// Extracts enrollment parameters from all available templates.
        /// </summary>
        public Dictionary<string, string> GetEnrollmentParameters()
        {
            EnsureTemplatesLoaded();

            var enrollmentParams = new Dictionary<string, string>();

            foreach (var template in _templateCache.Values)
            {
                try
                {
                    JObject jsonObject = JObject.Parse(template);
                    ExtractParamsFromJsonObject(jsonObject, enrollmentParams);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning($"Error extracting params from template: {ex.Message}");
                }
            }

            return enrollmentParams;
        }

        private void EnsureTemplatesLoaded()
        {
            if (_templateCache != null)
                return;

            _templateCache = new Dictionary<string, string>();

            if (HasJsonTemplates)
            {
                LoadTemplatesFromJsonConfig();
            }
            else
            {
                LoadTemplatesFromDirectory();
            }
        }

        private void LoadTemplatesFromJsonConfig()
        {
            _logger?.LogTrace("Loading templates from JSON configuration");

            try
            {
                JArray templatesArray = JArray.Parse(_config.TemplatesJson);

                foreach (JObject template in templatesArray)
                {
                    var profileObject = template["profile"];
                    string profileId = profileObject?["id"]?.ToString();

                    if (!string.IsNullOrEmpty(profileId))
                    {
                        _templateCache[profileId] = template.ToString();
                        _logger?.LogTrace($"Loaded template for profile: {profileId}");
                    }
                }

                _logger?.LogInformation($"Loaded {_templateCache.Count} templates from JSON configuration");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to parse TemplatesJson: {ex.Message}");
                throw new InvalidOperationException("Failed to parse TemplatesJson configuration. Ensure it is a valid JSON array of templates.", ex);
            }
        }

        private void LoadTemplatesFromDirectory()
        {
            string templateDir = GetTemplateDirectory();
            _logger?.LogTrace($"Loading templates from directory: {templateDir}");

            if (!Directory.Exists(templateDir))
            {
                _logger?.LogWarning($"Template directory does not exist: {templateDir}");
                return;
            }

            string[] jsonFiles = Directory.GetFiles(templateDir, "*.json");

            foreach (string jsonFile in jsonFiles)
            {
                try
                {
                    string jsonContent = File.ReadAllText(jsonFile);
                    JObject jsonObject = JObject.Parse(jsonContent);

                    var profileObject = jsonObject["profile"];
                    string profileId = profileObject?["id"]?.ToString();

                    if (!string.IsNullOrEmpty(profileId))
                    {
                        _templateCache[profileId] = jsonContent;
                        _logger?.LogTrace($"Loaded template from file {jsonFile} for profile: {profileId}");
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning($"Error loading template from {jsonFile}: {ex.Message}");
                }
            }

            _logger?.LogInformation($"Loaded {_templateCache.Count} templates from directory");
        }

        private Dictionary<string, string> ExtractProfileIdsFromJsonConfig()
        {
            var profileIds = new Dictionary<string, string>();

            try
            {
                JArray templatesArray = JArray.Parse(_config.TemplatesJson);

                foreach (JObject template in templatesArray)
                {
                    var profileObject = template["profile"];
                    string profileId = profileObject?["id"]?.ToString();

                    if (!string.IsNullOrEmpty(profileId))
                    {
                        // Use profileId as both key and value for JSON-based templates
                        profileIds[profileId] = profileId;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to extract profile IDs from TemplatesJson: {ex.Message}");
            }

            return profileIds;
        }

        private Dictionary<string, string> ExtractProfileIdsFromDirectory(string directoryPath)
        {
            var profileIds = new Dictionary<string, string>();

            if (!Directory.Exists(directoryPath))
            {
                _logger?.LogWarning($"Template directory does not exist: {directoryPath}");
                return profileIds;
            }

            string[] jsonFiles = Directory.GetFiles(directoryPath, "*.json");

            foreach (string jsonFile in jsonFiles)
            {
                try
                {
                    string jsonContent = File.ReadAllText(jsonFile);
                    JObject jsonObject = JObject.Parse(jsonContent);

                    var profileObject = jsonObject["profile"];
                    string profileId = profileObject?["id"]?.ToString();

                    if (!string.IsNullOrEmpty(profileId))
                    {
                        profileIds[jsonFile] = profileId;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning($"Error processing template file {jsonFile}: {ex.Message}");
                }
            }

            return profileIds;
        }

        private string GetTemplateDirectory()
        {
            if (!string.IsNullOrEmpty(_config?.TemplateDirectory))
            {
                string templateDir = _config.TemplateDirectory;

                if (!Path.IsPathRooted(templateDir))
                {
                    string basePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                    templateDir = Path.Combine(basePath, templateDir);
                }

                return templateDir.TrimEnd(Path.DirectorySeparatorChar, '/') + Path.DirectorySeparatorChar;
            }

            string codeBase = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(codeBase) + Path.DirectorySeparatorChar;
        }

        private void ExtractParamsFromJsonObject(JToken jsonToken, Dictionary<string, string> enrollmentParams)
        {
            if (jsonToken is JObject jObject)
            {
                foreach (var property in jObject.Properties())
                {
                    string propertyValue = property.Value.ToString();

                    if (propertyValue.StartsWith("EnrollmentParam|") || propertyValue.StartsWith("Numeric|EnrollmentParam|"))
                    {
                        string paramName = ExtractParamName(propertyValue);
                        string paramType = propertyValue.Contains("Numeric|") ? "Number" : "String";

                        if (!enrollmentParams.ContainsKey(paramName))
                        {
                            enrollmentParams[paramName] = paramType;
                        }
                    }

                    ExtractParamsFromJsonObject(property.Value, enrollmentParams);
                }
            }
            else if (jsonToken is JArray jArray)
            {
                foreach (var item in jArray)
                {
                    ExtractParamsFromJsonObject(item, enrollmentParams);
                }
            }
        }

        private string ExtractParamName(string enrollmentParam)
        {
            var parts = enrollmentParam.Split('|');
            if (parts.Length == 2 && parts[0] == "EnrollmentParam")
            {
                return parts[1];
            }

            if (parts.Length == 4 && parts[0] == "Numeric" && parts[1] == "EnrollmentParam")
            {
                return parts[2];
            }

            return parts.Length > 1 ? parts[1] : "Unknown";
        }
    }
}
