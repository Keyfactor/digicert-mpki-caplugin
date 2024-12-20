// Copyright 2023 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// thespecific language governing permissions and limitations under the       
// License. 
﻿using System.Collections.Generic;
using Newtonsoft.Json;

namespace Keyfactor.AnyGateway.DigicertMpki.Client.Models
{
    public class Attributes
    {
        [JsonProperty("common_name", NullValueHandling = NullValueHandling.Ignore)] public string CommonName { get; set; }

        [JsonProperty("content_type", NullValueHandling = NullValueHandling.Ignore)] public string ContentType { get; set; }

        [JsonProperty("counter_signature", NullValueHandling = NullValueHandling.Ignore)] public string CounterSignature { get; set; }

        [JsonProperty("country", NullValueHandling = NullValueHandling.Ignore)] public string Country { get; set; }

        [JsonProperty("custom_attributes", NullValueHandling = NullValueHandling.Ignore)] public CustomAttributes CustomAttributes { get; set; }

        [JsonProperty("dn_qualifier", NullValueHandling = NullValueHandling.Ignore)] public string DnQualifier { get; set; }

        [JsonProperty("domain_component", NullValueHandling = NullValueHandling.Ignore)] public List<DomainComponent> DomainComponent { get; set; }

        [JsonProperty("domain_name", NullValueHandling = NullValueHandling.Ignore)] public string DomainName { get; set; }

        [JsonProperty("email", NullValueHandling = NullValueHandling.Ignore)] public string Email { get; set; }


        [JsonProperty("given_name", NullValueHandling = NullValueHandling.Ignore)] public string GivenName { get; set; }

        [JsonProperty("ip_address", NullValueHandling = NullValueHandling.Ignore)] public string IpAddress { get; set; }

        [JsonProperty("job_title", NullValueHandling = NullValueHandling.Ignore)] public string JobTitle { get; set; }

        [JsonProperty("locality", NullValueHandling = NullValueHandling.Ignore)] public string Locality { get; set; }

        [JsonProperty("message_digest", NullValueHandling = NullValueHandling.Ignore)] public string MessageDigest { get; set; }

        [JsonProperty("organization_name", NullValueHandling = NullValueHandling.Ignore)] public string OrganizationName { get; set; }

        [JsonProperty("organization_unit", NullValueHandling = NullValueHandling.Ignore)] public List<OrganizationUnit> OrganizationUnit { get; set; }

        [JsonProperty("postal_code", NullValueHandling = NullValueHandling.Ignore)] public string PostalCode { get; set; }

        [JsonProperty("pseudonym", NullValueHandling = NullValueHandling.Ignore)] public string Pseudonym { get; set; }

        [JsonProperty("san", NullValueHandling = NullValueHandling.Ignore)] public DigicertSan San { get; set; }

        [JsonProperty("serial_number", NullValueHandling = NullValueHandling.Ignore)] public string SerialNumber { get; set; }

        [JsonProperty("signing_time", NullValueHandling = NullValueHandling.Ignore)] public string SigningTime { get; set; }

        [JsonProperty("state", NullValueHandling = NullValueHandling.Ignore)] public string State { get; set; }

        [JsonProperty("street_address", NullValueHandling = NullValueHandling.Ignore)] public List<StreetAddress> StreetAddress { get; set; }

        [JsonProperty("surname", NullValueHandling = NullValueHandling.Ignore)] public string Surname { get; set; }

        [JsonProperty("unique_identifier", NullValueHandling = NullValueHandling.Ignore)] public string UniqueIdentifier { get; set; }

        [JsonProperty("unstructured_address", NullValueHandling = NullValueHandling.Ignore)] public string UnstructuredAddress { get; set; }

        [JsonProperty("unstructured_name", NullValueHandling = NullValueHandling.Ignore)] public string UnstructuredName { get; set; }

        [JsonProperty("user_id", NullValueHandling = NullValueHandling.Ignore)] public string UserId { get; set; }
    }
    
}