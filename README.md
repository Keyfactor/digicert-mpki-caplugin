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


The Clearpass AnyCA Gateway REST plugin extends the capabilities of Aruba Clearpass Onboard to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies :
* CA Sync:
    * Download all certificates issued to the customer by the Clearpass CA.
* Certificate enrollment for the Clearpass products listed in the manifest file:
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

### ClearPass Onboard: Setting Up an API Client

#### Step 1: Access ClearPass Admin Console
1. **Login** to the ClearPass Admin console using your administrator credentials.
2. Navigate to **Administration** > **API Services** > **API Clients**.

#### Step 2: Create a New API Client
1. Click on the **Add API Client** button to create a new API client.

#### Step 3: Configure the API Client

- **Client ID**:
  - Enter some value such as `Client1` in the **Client ID** field.
  - This is the value you will use in Keyfactor for the API Client ID when setting up the CA.

- **Description**:
  - You can provide a description for this API client, such as "Sample API client for testing purposes," in the **Description** field.

- **Enabled**:
  - Ensure the **Enabled** checkbox is selected. This means the API client will be active and able to make API calls.

- **Operating Mode**:
  - Select **ClearPass REST API - Client will be used for API calls to ClearPass** from the **Operating Mode** dropdown.

- **Operator Profile**:
  - Select **Super Administrator** from the **Operator Profile** dropdown.
  - This profile will provide the API client with the necessary permissions to interact with ClearPass.

- **Grant Type**:
  - Select **Client credentials (`grant_type=client_credentials`)** from the **Grant Type** dropdown.
  - This means the API client will authenticate using its client credentials.

- **Client Secret**:
  - Since this is a non-public client, ensure the **Generate a new client secret** checkbox is selected.
  - The system will generate a new client secret. For example, `FFFDDDCCCRRR4444DDDDDDDDDDD`.
  - **Note:** The client secret is used in the OAuth2 `client_secret` parameter and will be encrypted once stored, so be sure to copy it securely.

#### Step 4: Set Token Lifetimes

- **Access Token Lifetime**:
  - Enter `8` in the **Access Token Lifetime** field.
  - Select **hours** from the dropdown. This means the access token will be valid for 8 hours.

#### Step 5: Save the API Client
1. Once all fields are configured, click the **Create API Client** button to save the new API client.
2. If you need to cancel, click the **Cancel** button.

#### Step 6: Use the API Client
- Use the **Client ID** (`Client1`) and **Client Secret** (`FFFDDDCCCRRR4444DDDDDDDDDDD`) in your Gateway Configuration Settings.

---

### Getting the Certificate Authority ID in Aruba ClearPass Onboard

#### Steps to Get the Certificate Authority ID

1. **Log in to ClearPass Policy Manager**:
   - Open your web browser and navigate to the ClearPass Policy Manager login page.
   - Enter your credentials and log in.

2. **Navigate to the Certificate Authorities Page**:
   - Go to **Onboard** > **Certificate Authorities**.

3. **Select the Certificate Authority**:
   - Find the Certificate Authority you are interested in.
   - Click the **Edit** button next to the Certificate Authority.

4. **Locate the ID in the URL**:
   - Once the edit page opens, look at the URL in your browser's address bar.
   - The ID of the Certificate Authority will be part of the URL. It usually appears as a numeric value after `id=`.

5. **Command Gateway Translation**:
   - This will be used when setting up the Gateway as the CaId as explained in the Configuration section.

#### Note
At the time of writing, there was no API call available to get a list of Certificate Authorities in ClearPass Onboard. Therefore, this method of extracting the ID from the URL was the only known way to obtain it.

---

### Aruba ClearPass Onboard Trust Chain Bundle Download

#### Steps to Download a Trust Chain Bundle

1. **Log in to ClearPass Policy Manager**:
   - Open your web browser and navigate to the ClearPass Policy Manager login page.
   - Enter your credentials and log in.

2. **Navigate to the Certificate Authority Trust Chain Page**:
   - Go to **Onboard** > **Certificate Authorities**.
   - Click on the appropriate **Certificate Authority**.
   - Click the **Trust Chain** link.

3. **Download the Trust Chain Bundle**:
   - Click the **Download Bundle** link on the Certificate Authority Trust Chain page.
   - The **Export Certificate** form will open.
   - In the **Format** row, choose the certificate format.
   - Follow the prompts to download the trust chain bundle.

4. **Save the Bundle**:
   - Save the downloaded bundle to a secure location on your computer.
   
5. **Using The Intermediate Certificate**:
   - Extract the Intermediate Certificate from the Bundle.  This will be the certificate used when setting up the CA on the Gateway.

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

        Each defined Certificate Authority in the AnyCA Gateway REST can support one issuing certificate authority. Since Aruba ClearPass Onboard has multiple available Certificate Authorities, if you require certificate enrollment from multiple Aruba ClearPass Certificate Authorities, you must define multiple Certificate Authorities in the AnyCA Gateway REST. This will manifest in Command as one Aruba ClearPass CA per defined Certificate Authority.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **ApiKey** - Digicert mPKI Rest API Key 
        * **DigiCertSymUrl** - Base Url for Digicert mPKI REST API such as https://someurl/mpki/api/v1 
        * **ClientCertLocation** - Location on the Gateway Server File System of Client Certificate sample: C:\temp\myclientcert.pfx 
        * **ClientCertPassword** - Password for the SOAP Client Certificate. 
        * **EndpointAddress** - Endpoint address for SOAP Service sample: https://someurl/pki-ws/certificateManagementService. 
        * **OuStartPoint** - Value of the OuStartPoint Name that digicert expects in the API. 

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).