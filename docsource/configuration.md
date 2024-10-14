## Overview

The Clearpass AnyCA Gateway REST plugin extends the capabilities of Aruba Clearpass Onboard to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies :
* CA Sync:
    * Download all certificates issued to the customer by the Clearpass CA.
* Certificate enrollment for the Clearpass products listed in the manifest file:
    * Support certificate enrollment (new keys/certificate)
        * Support certificate re-issuance/renewal (new public/private keys with the same or different domain names).
* Certificate revocation:
    * Request revocation of a previously issued certificate.

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

## Gateway Registration

Each defined Certificate Authority in the AnyCA Gateway REST can support one issuing certificate authority. Since Aruba ClearPass Onboard has multiple available Certificate Authorities, if you require certificate enrollment from multiple Aruba ClearPass Certificate Authorities, you must define multiple Certificate Authorities in the AnyCA Gateway REST. This will manifest in Command as one Aruba ClearPass CA per defined Certificate Authority.

