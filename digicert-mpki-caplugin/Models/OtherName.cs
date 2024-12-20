// Copyright 2023 Keyfactor                                                   
// Licensed under the Apache License, Version 2.0 (the "License"); you may    
// not use this file except in compliance with the License.  You may obtain a 
// copy of the License at http://www.apache.org/licenses/LICENSE-2.0.  Unless 
// required by applicable law or agreed to in writing, software distributed   
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES   
// OR CONDITIONS OF ANY KIND, either express or implied. See the License for  
// thespecific language governing permissions and limitations under the       
// License. 
using Newtonsoft.Json;

namespace Keyfactor.AnyGateway.DigicertMpki.Client.Models
{
    public class OtherName
    {
        [JsonProperty("id", NullValueHandling = NullValueHandling.Ignore)] public string Id { get; set; }
        [JsonProperty("mandatory", NullValueHandling = NullValueHandling.Ignore)] public bool Mandatory { get; set; }
        [JsonProperty("type", NullValueHandling = NullValueHandling.Ignore)] public string Type { get; set; }
        [JsonProperty("value", NullValueHandling = NullValueHandling.Ignore)] public string Value { get; set; }
    }
}
