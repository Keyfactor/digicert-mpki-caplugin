## Overview

This gateway integration supports the Digicert MPKI platform:
* CA Sync:
    * Download all certificates issued to the customer by the Digicert MPKI for a defined set of profiles.
* Certificate enrollment for the Digicert MPKI products listed in the manifest file:
    * Support certificate enrollment (new keys/certificate)
        * Support certificate re-issuance/renewal (new public/private keys with the same or different domain names).
* Certificate revocation:
    * Request revocation of a previously issued certificate.

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
![](/images/SampleMapping.gif)

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

## Certificate Template Creation Step

TODO Certificate Template Creation Step is a required section

## Gateway Registration

TODO Gateway Registration is a required section

