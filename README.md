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

        * **ApiKey** - Digicert mPKI REST API Key. Can also be set via `DIGICERT_API_KEY` environment variable.
        * **DigiCertSymUrl** - Base Url for Digicert mPKI REST API such as https://someurl/mpki/api/v1
        * **ClientCertLocation** - Path to the client certificate PFX file.
            * Windows: `C:\temp\myclientcert.pfx`
            * Linux/Container: `/secrets/client.pfx`
            * Can alternatively set `DIGICERT_CLIENT_CERT_BASE64` environment variable with base64-encoded PFX.
        * **ClientCertPassword** - Password for the SOAP Client Certificate. Can also be set via `DIGICERT_CLIENT_CERT_PASSWORD` environment variable.
        * **EndpointAddress** - Endpoint address for SOAP Service sample: https://someurl/pki-ws/certificateManagementService.
        * **TemplateDirectory** - (Optional) Directory containing enrollment template JSON files. Supports absolute paths for container volume mounts (e.g., `/templates`). If not specified, defaults to the plugin assembly directory.
        * **TemplatesJson** - (Optional) JSON array containing all enrollment templates inline. When provided, templates are loaded from this config value instead of files. This simplifies container deployments by eliminating the need for volume mounts. Takes precedence over `TemplateDirectory`. See [Inline Templates Configuration](#inline-templates-configuration) below.

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.



## Inline Templates Configuration

For simplified deployments (especially containers), you can embed all enrollment templates directly in the CA Connection configuration using the `TemplatesJson` field. This eliminates the need for template file mounts.

### Format

The `TemplatesJson` value should be a JSON array containing all enrollment templates:

```json
[
  {
    "profile": {
      "id": "2.16.840.1.113733.1.16.1.5.2.5.1.1280209757"
    },
    "csr": "CSR|RAW",
    "seat": {
      "seat_id": "EnrollmentParam|Seat"
    },
    "validity": {
      "unit": "years",
      "duration": "Numeric|EnrollmentParam|Validity (Years)|Numeric"
    },
    "attributes": {
      "common_name": "CSR|CN",
      "country": "CSR|C",
      "organization_name": "CSR|O"
    }
  },
  {
    "profile": {
      "id": "2.16.840.1.101.2.1.11.39"
    },
    "csr": "CSR|RAW",
    "validity": {
      "years": 1
    },
    "attributes": {
      "common_name": "CSR|CN",
      "email": "EnrollmentParam|Email"
    }
  }
]
```

### Precedence

When both `TemplatesJson` and `TemplateDirectory` are configured:
- `TemplatesJson` takes precedence and templates are loaded from the inline JSON
- `TemplateDirectory` is ignored

### Advantages for Container Deployments

Using `TemplatesJson` instead of file-based templates provides several benefits:
- **No volume mounts required**: Templates are stored in the CA Connection configuration
- **Simpler Kubernetes deployments**: No need for ConfigMaps for template files
- **Single source of truth**: All configuration in one place
- **Easier updates**: Change templates through the AnyCA Gateway REST portal without redeploying

## Container Deployment

This plugin supports deployment in containerized environments (Docker, Kubernetes). The following features enable container-native configuration patterns:

### Environment Variables

Sensitive configuration values can be injected via environment variables (config file values take precedence when both are provided):

| Environment Variable | Description | Config Equivalent |
|---------------------|-------------|-------------------|
| `DIGICERT_API_KEY` | DigiCert mPKI REST API Key | ApiKey |
| `DIGICERT_CLIENT_CERT_PASSWORD` | Password for the SOAP client certificate | ClientCertPassword |
| `DIGICERT_CLIENT_CERT_BASE64` | Base64-encoded PFX certificate (alternative to file path) | ClientCertLocation |

### Volume Mounts

For container deployments, you can mount certificates and templates from external sources:

- **Client Certificate**: Mount the PFX file and set `ClientCertLocation` to the mount path (e.g., `/secrets/client.pfx`)
- **Enrollment Templates**: Mount template JSON files and set `TemplateDirectory` to the mount path (e.g., `/templates`)

### Docker Example

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:6.0

# Copy AnyCA Gateway REST and plugin
COPY ./gateway /app
COPY ./templates /app/templates

WORKDIR /app

# Environment variables for secrets (alternatively use Docker secrets)
ENV DIGICERT_API_KEY=""
ENV DIGICERT_CLIENT_CERT_PASSWORD=""
ENV DIGICERT_CLIENT_CERT_BASE64=""

ENTRYPOINT ["dotnet", "Keyfactor.AnyGateway.dll"]
```

### Docker Compose Example

```yaml
version: '3.8'
services:
  anyca-gateway:
    image: your-registry/anyca-gateway:latest
    environment:
      - DIGICERT_API_KEY=${DIGICERT_API_KEY}
      - DIGICERT_CLIENT_CERT_PASSWORD=${DIGICERT_CLIENT_CERT_PASSWORD}
    volumes:
      - ./secrets/client.pfx:/secrets/client.pfx:ro
      - ./templates:/app/templates:ro
    ports:
      - "5000:5000"
```

### Kubernetes Example

#### Create Secrets

```bash
# Create secret for client certificate
kubectl create secret generic digicert-client-cert \
  --from-file=client.pfx=./client.pfx

# Create secret for sensitive values
kubectl create secret generic digicert-credentials \
  --from-literal=api-key='your-api-key' \
  --from-literal=cert-password='your-cert-password'
```

#### Create ConfigMap for Templates

```bash
kubectl create configmap digicert-templates \
  --from-file=./templates/
```

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anyca-gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: anyca-gateway
  template:
    metadata:
      labels:
        app: anyca-gateway
    spec:
      containers:
      - name: anyca-gateway
        image: your-registry/anyca-gateway:latest
        env:
        - name: DIGICERT_API_KEY
          valueFrom:
            secretKeyRef:
              name: digicert-credentials
              key: api-key
        - name: DIGICERT_CLIENT_CERT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: digicert-credentials
              key: cert-password
        volumeMounts:
        - name: client-cert
          mountPath: /secrets
          readOnly: true
        - name: templates
          mountPath: /app/templates
          readOnly: true
      volumes:
      - name: client-cert
        secret:
          secretName: digicert-client-cert
      - name: templates
        configMap:
          name: digicert-templates
```

#### CA Connection Configuration for Kubernetes

When configuring the CA Connection in the AnyCA Gateway REST portal for Kubernetes deployments:

| Field | Value |
|-------|-------|
| ApiKey | (leave empty - using environment variable) |
| DigiCertSymUrl | https://your-digicert-url/mpki/api/v1 |
| ClientCertLocation | /secrets/client.pfx |
| ClientCertPassword | (leave empty - using environment variable) |
| EndpointAddress | https://your-digicert-url/pki-ws/certificateManagementService |
| TemplateDirectory | /app/templates (if using file mounts) |
| TemplatesJson | `[{"profile":{"id":"..."},...}]` (alternative to TemplateDirectory - recommended for simpler deployments) |

### Using Base64-Encoded Certificate

As an alternative to mounting the certificate file, you can provide the certificate as a base64-encoded string via environment variable:

```bash
# Encode the certificate
export DIGICERT_CLIENT_CERT_BASE64=$(base64 -w0 client.pfx)

# In Kubernetes, create the secret
kubectl create secret generic digicert-cert-base64 \
  --from-literal=cert-base64="$(base64 -w0 client.pfx)"
```

Then reference in your deployment:

```yaml
env:
- name: DIGICERT_CLIENT_CERT_BASE64
  valueFrom:
    secretKeyRef:
      name: digicert-cert-base64
      key: cert-base64
```

When using base64-encoded certificate, you can leave `ClientCertLocation` empty in the CA Connection configuration.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).