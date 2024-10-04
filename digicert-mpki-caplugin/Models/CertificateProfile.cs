using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace Keyfactor.Extensions.CAPlugin.DigicertMpki.Models
{
    public class Attribute
    {
        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)]
        public string Type { get; set; }

        [JsonProperty("mandatory", NullValueHandling = NullValueHandling.Ignore)]
        public bool Mandatory { get; set; }

        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get; set; }
    }

    public class Authentication
    {
        [JsonProperty("method_id", NullValueHandling = NullValueHandling.Ignore)]
        public string MethodId { get; set; }

        [JsonProperty("method", NullValueHandling = NullValueHandling.Ignore)]
        public string Method { get; set; }

        [JsonProperty("approval", NullValueHandling = NullValueHandling.Ignore)]
        public string Approval { get; set; }
    }

    public class Certificate
    {
        [JsonProperty("subject", NullValueHandling = NullValueHandling.Ignore)]
        public Subject Subject { get; set; }

        [JsonProperty("validity", NullValueHandling = NullValueHandling.Ignore)]
        public Validity Validity { get; set; }

        [JsonProperty("extensions", NullValueHandling = NullValueHandling.Ignore)]
        public Extensions Extensions { get; set; }

        [JsonProperty("issuer", NullValueHandling = NullValueHandling.Ignore)]
        public Issuer Issuer { get; set; }
    }

    public class Enrollment
    {
        [JsonProperty("client_type_id", NullValueHandling = NullValueHandling.Ignore)]
        public string ClientTypeId { get; set; }

        [JsonProperty("client_type", NullValueHandling = NullValueHandling.Ignore)]
        public string ClientType { get; set; }
    }

    public class Extensions
    {
        [JsonProperty("san", NullValueHandling = NullValueHandling.Ignore)]
        public San San { get; set; }
    }

    public class Issuer
    {
        [JsonProperty("serial_number", NullValueHandling = NullValueHandling.Ignore)]
        public string SerialNumber { get; set; }

        [JsonProperty("subject_dn", NullValueHandling = NullValueHandling.Ignore)]
        public string SubjectDn { get; set; }

        [JsonProperty("certificate", NullValueHandling = NullValueHandling.Ignore)]
        public string Certificate { get; set; }

        [JsonProperty("root", NullValueHandling = NullValueHandling.Ignore)]
        public bool Root { get; set; }
    }

    public class KeyEscrowPolicy
    {
        [JsonProperty("key_escrow_enabled", NullValueHandling = NullValueHandling.Ignore)]
        public bool KeyEscrowEnabled { get; set; }

        [JsonProperty("do_key_recovery_for_additional_enroll_request", NullValueHandling = NullValueHandling.Ignore)]
        public bool DoKeyRecoveryForAdditionalEnrollRequest { get; set; }
    }

    public class PrivateKeyAttributes
    {
        [JsonProperty("key_size", NullValueHandling = NullValueHandling.Ignore)]
        public int KeySize { get; set; }

        [JsonProperty("key_sizes", NullValueHandling = NullValueHandling.Ignore)]
        public List<int> KeySizes { get; set; }

        [JsonProperty("key_escrow_policy", NullValueHandling = NullValueHandling.Ignore)]
        public KeyEscrowPolicy KeyEscrowPolicy { get; set; }

        [JsonProperty("key_exportable", NullValueHandling = NullValueHandling.Ignore)]
        public bool KeyExportable { get; set; }
    }

    public class CertificateProfile
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)]
        public string Id { get; set; }

        [JsonProperty("name", NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty("status", NullValueHandling = NullValueHandling.Ignore)]
        public string Status { get; set; }

        [JsonProperty("signature_algorithm", NullValueHandling = NullValueHandling.Ignore)]
        public string SignatureAlgorithm { get; set; }

        [JsonProperty("publish_to_public_directory", NullValueHandling = NullValueHandling.Ignore)]
        public bool PublishToPublicDirectory { get; set; }

        [JsonProperty("renewal_period_days", NullValueHandling = NullValueHandling.Ignore)]
        public int RenewalPeriodDays { get; set; }

        [JsonProperty("duplicate_cert_policy", NullValueHandling = NullValueHandling.Ignore)]
        public bool DuplicateCertPolicy { get; set; }

        [JsonProperty("certificate_delivery_format", NullValueHandling = NullValueHandling.Ignore)]
        public string CertificateDeliveryFormat { get; set; }

        [JsonProperty("certificate", NullValueHandling = NullValueHandling.Ignore)]
        public Certificate Certificate { get; set; }

        [JsonProperty("private_key_attributes", NullValueHandling = NullValueHandling.Ignore)]
        public PrivateKeyAttributes PrivateKeyAttributes { get; set; }

        [JsonProperty("enrollment", NullValueHandling = NullValueHandling.Ignore)]
        public Enrollment Enrollment { get; set; }

        [JsonProperty("authentication", NullValueHandling = NullValueHandling.Ignore)]
        public Authentication Authentication { get; set; }
    }

    public class San
    {
        [JsonProperty("critical", NullValueHandling = NullValueHandling.Ignore)]
        public bool Critical { get; set; }

        [JsonProperty("attributes", NullValueHandling = NullValueHandling.Ignore)]
        public List<Attribute> Attributes { get; set; }
    }

    public class Subject
    {
        [JsonProperty("attributes", NullValueHandling = NullValueHandling.Ignore)]
        public List<Attribute> Attributes { get; set; }
    }

    public class Validity
    {
        [JsonProperty("unit", NullValueHandling = NullValueHandling.Ignore)]
        public string Unit { get; set; }

        [JsonProperty("duration", NullValueHandling = NullValueHandling.Ignore)]
        public int Duration { get; set; }
    }
}
