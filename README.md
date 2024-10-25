<h1 align="center" style="border-bottom: none">
    Digicert Mpki   Gateway AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-pilot-3D1973?style=flat-square" alt="Integration Status: pilot" />
<a href="https://github.com/Keyfactor/digicert-mpki-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/digicert-mpki-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/digicert-mpki-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/digicert-mpki-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


This gateway integration supports the Digicert MPKI platform:
* CA Sync:
    * Download all certificates issued to the customer by the Digicert MPKI for a defined set of profiles.
* Certificate enrollment for the Digicert MPKI products listed in the manifest file:
    * Support certificate enrollment (new keys/certificate)
        * Support certificate re-issuance/renewal (new public/private keys with the same or different domain names).
* Certificate revocation:
    * Request revocation of a previously issued certificate.

## Compatibility

The Digicert Mpki   Gateway AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The Digicert Mpki   Gateway AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

---

### Digicert MPKI Onboard: Setting Up an API Access

#### SOAP Inventory Setup

The Digicert mPKI REST API does not support inventory so the SOAP API is required to inventory all of the certs for the profiles listed in config.json file.
In order to use the SOAP API, you need a client certificate from the Digicert mPKI Portal.  The steps to obtain a certfificate are outlined in the documentation
listed [here](https://knowledge.digicert.com/content/dam/digicertknowledgebase/attachments/pki-platform/soap-api-client-package/pki-web-services-developers-guide.pdf).

1) Follow the instructions in section 2.6.1 of the above document.
2) Export the keystore to a PFX file with a similar command that is listed below:
```keytool -importkeystore -srckeystore KeyfactorMPki.jks -srcstoretype JKS -destkeystore KeyfactorMPki3.pfx -deststoretype PKCS12```
3) Import the PFX Certificate to the computer it was generated on.
4) Export the PFX to a file from that same machine's certificate store and copy it to the same directory where the config.json is located.

Sample Commands for a Test Envrionment are below:
```
keytool -genkey -alias pki_ra -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -dname "CN=pki_ra" -keypass SomePassword -keystore KeyfactorMPki3 -storepass SomePassword

keytool -certreq -alias pki_ra -sigalg SHA256withRSA -file pki_raCSR.req -keypass SomePassword -keystore KeyfactorMPki2 -storepass SomePassword

keytool -import -alias pki_ra -file cert.p7b -noprompt -keypass SomePassword -keystore KeyfactorMPki2 -storepass SomePassword

keytool -import -trustcacerts -alias pki_ca -file SYMC_Test_Drive_RA_Intermediate_CA.cer -keystore KeyfactorMPki2 -storepass SomePassword

keytool -import -trustcacerts -alias root -file SYMC_Managed_PKI_Infrastructure_Test_Drive_Root.cer -keystore KeyfactorMPki2 -storepass SomePassword

keytool -importkeystore -srckeystore KeyfactorMPki.jks -srcstoretype JKS -destkeystore KeyfactorMPki2.pfx -deststoretype PKCS12
```
---

#### Enrollment Templates
Since there are infinate number of profile configurations in DigiCertSym mPKI, these tempates are used to shell out the request for each profile and during the enrollment process will be replaced with data from the Enrollment request in Keyfactor.

These tempates files must be copied into the same directory as the Gateway binaries and saved as a JSON file with the same name outlined in the tempates section above.

Sample Enrollment Template is [here](https://github.com/Keyfactor/digicert-mpki-caplugin/blob/main/FAA-StandardRequest.json)

Enrollment Format Specifications Located [here](https://pki-ws-rest.symauth.com/mpki/docs/index.html)

1) **EnrollmentParam** - Below is a sample Enrollment Template where anything Prefixed with "EnrollmentParam|FieldName" will be replaced with an enrollment field value from the Keyfactor portal during enrollment. 
2) **CSR|RAW** - Below is a sample Enrollment Template where anything Prefixed with "CSR|RAW" will be replaced with the raw CSR content from the enrollment request from Keyfactor Portal. 
3) **CSR|CSRContent** - Below is a sample Enrollment Template where anything Prefixed with "CSR|CSRContent" will be replaced with the CSR content from the enrollment request from Keyfactor Portal. 

```
{
	"profile": {
		"id": "2.16.840.1.113733.1.16.1.5.2.5.1.1280209757"
	},
	"seat": {
		"seat_id": "EnrollmentParam|Seat"
	},
	"csr": "CSR|RAW",
	"validity": {
		"unit": "years",
		"duration": "Numeric|EnrollmentParam|Validity (Years)|Numeric"
	},
	"attributes": {
		"common_name": "CSR|CN",
		"country": "CSR|C",
		"organization_name": "CSR|O"
	}
}
```

4) **Sample Mapping Below**
![](../images/SampleMapping.gif)

---

### Digicert Trust Chain Bundle Download

#### Steps to Download a Trust Chain Bundle

1. **Log in to Digicert MPKI Manager**:
   - Open your web browser and navigate to the Digicert MPKI URL.
   - Enter your pin and log in.

2. **Navigate to the Manage CAs Menu**:
   - Click on Gear at the bottom of page.
   - Select **Manage CAs**.

3. **Download the Trust Chain Bundle**:
   - You will see the root and intermediate certificates available for download.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [Digicert Mpki   Gateway AnyCA Gateway REST plugin](https://github.com/Keyfactor/digicert-mpki-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0`) to the Extensions directory:

    ```shell
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    ```

    > The directory containing the Digicert Mpki   Gateway AnyCA Gateway REST plugin DLLs (`net6.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the Digicert Mpki   Gateway plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        TODO Gateway Registration is a required section

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **ApiKey** - Digicert mPKI Rest API Key 
        * **DigiCertSymUrl** - Base Url for Digicert mPKI REST API such as https://someurl/mpki/api/v1 
        * **ClientCertLocation** - Location on the Gateway Server File System of Client Certificate sample: C:\temp\myclientcert.pfx 
        * **ClientCertPassword** - Password for the SOAP Client Certificate. 
        * **EndpointAddress** - Endpoint address for SOAP Service sample: https://someurl/pki-ws/certificateManagementService. 

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).