# Possession Credential

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Overview](#overview)
- [Background & Problem Statement](#background--problem-statement)
- [Proposal](#proposal)
  - [Proposal Overview](#proposal-overview)
  - [Proposed APIs](#proposed-apis)
- [Existing Proposals & Standards](#existing-proposals--standards)
  - [TrustToken](#trusttoken)
  - [Browser Cookies](#browser-cookies)
  - [WebID](#webid)
- [Privacy & Security](#privacy--security)
- [Acknowledgements](#acknowledgements)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Overview

This explainer defines a proposal to make the browser a 'possession factor'. It rests on the concept of enabling the browser to replace other possession factors (such as a phone number or an app) by issuing a public-private key pair and uniquely assigning it to a specific user on that browser, for that domain. The design also aims to be privacy friendly and include consumer consent during the credential creation process. The ultimate goal is to create a better user experience for internet users where a possession factor authentication is required during payments.

The new possession credential is an extension of the existing [PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential) interface, which forms part of the [Credential Management API](https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API). It consists of a public-private key pair which is stored by the browser and can be used in a manner similar to a [WebAuthn](https://www.w3.org/TR/webauthn/) credential. Like WebAuthn, it will be able to provide an assertion to a challenge, but it will not require explicit user interaction with hardware, thereby limiting additional user friction.

For registration, a customer will be authenticated using their existing authentication mechanism (e.g. SMS OTP) to their Relying Party (RP). Once authenticated, the customer will be offered the opportunity to "trust" their browser to be used as a possession credential for authentication in future. If consent is given, the browser will generate a public-private key pair and return a new credential ID, which is sent to the Relying Party (RP) to store as credential reference.

The new possession credential can used as part of a [Secure Payment Confirmation](https://github.com/rsolomakhin/secure-payment-confirmation) (SPC) flow during a 3D Secure payment, on a previously trusted browser with minimal user interaction, offering an improved checkout experience.

## Background & Problem Statement

Research [[1]](http://cdn2.hubspot.net/hubfs/464903/Ethoca%20Research%20Report%20-%20False%20Declines.pdf?submissionGuid=f8039048-f189-406f-a43c-8643db211e4a) [[2]](https://www.linkedin.com/posts/deanjordaan_microsoft-sca-scorecard-january-2021-activity-6763544872361320448-uIo-?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3BvdUSYY0qTMeN1JXuwWnjLg%3D%3D) shows that a large percentage of ecommerce transactions are abandoned during the checkout journey, with a big portion of cart abandonment believed to be directly related to friction and unpredictable UX during the checkout process. Where no customer challenge is performed, it can lead to higher false decline rates due to suspected fraud. Customer trust in the merchant is eroded if they are not afforded the opportunity to prove their identity via a challenge before a transaction is outright declined.

Performing a challenge with a "good" amount of friction seems to be the perfect middle ground during medium risk transactions. Secure Payment Confirmation (SPC) aims to address this by requiring the customer to authenticate using their FIDO token. This allows the merchant to challenge their customer while offering a predictable UX experience. WebAuthn isn't always a low friction, single-click experience - certain devices does not have biometrics and require a PIN / screen pattern, leading to even more friction.

The new possession credential aims to establish the browser as a powerful possession factor that can be used by the customer to authenticate during the 3DS challenge flow using a single-click. This leads to lower customer friction and also offers broader browser support when compared to WebAuthn.

## Proposal

### Proposal Overview

The web browser and customer combination can be seen as a possession factor that can be leveraged to perform customer authentication. In a similar fashion to WebAuthn, a browser possession credential can be generated on the browser and used to sign a server challenge during authentication.

The new possession credential will rely on the existing PublicKeyCredential interface as definition. To enable this, an internal change would be required to the PublicKeyCredential interface to support a new "possession" type.

![Alt text](img/system.png?raw=true "Registration")
_Source: Adapted from Chrome team_

**Registration**

During the registration step, a unique public-private key pair is generated on the browser, specific to a Relying Party (RP). The private key is unique to the browser and stored securely using the best available mechanism as a non-extractable [CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) object.

To enable the possession credential to be used as part of the SPC flow, the customer would need to have been authenticated and logged in on the RP's domain. In this context the customer will then register a new possession credential to be used with a payment credential. When registration is done, the new credential ID will be reported to the Relying Party to store:

![Alt text](img/registration.png?raw=true "Registration")

![Alt text](img/registration-2.png?raw=true "Registration 2")

**Authentication**

During authentication, a server challenge is signed using the private key to which the credential ID corresponds.
Since the PublicKeyCredential interface is re-used, the existing Credential Management APIs can be used for registration and authentication. See the [Proposed APIs](#proposed-apis) section for a detailed explanation.

The Relying Party includes a list of credentials it will allow to be used for authentication, and the browser prompts the customer to use their browser possession credential to authenticate:

![Alt text](img/auth.png?raw=true "Auth 1")

After the customer has provided a user gesture by selecting the "Confirm" button, the server challenge is signed and the response can be submitted to the Relying Party.

As shown in the screenshots above, the credential should be compatible with the new SPC API, which relies on a PublicKeyCredential as part of its initialization to setup a payment authentication request. When the new type of PublicKeyCredential is used, the customer will be prompted with UI similar to the SPC challenge UI, but no user verification step will occur.

The browser possession credential relies on elements from existing W3C concepts:

- [**WebCrypto**](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)

  Generate public-private key pairs and sign challenges.

- [**Credential Management L1**](https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API)

  Use the existing navigator.credentials.create() and navigator.credentials.get() APIs to support the new PublicKeyCredential with type "possession".

- [**SPC**](https://github.com/rsolomakhin/secure-payment-confirmation)

  By using a known PublicKeyCredential object, the SPC flow should be able to support the new credential with minimal changes.

### Proposed APIs

**Possession Credential Creation**

Registration will still rely on a PublicKeyCredentialCreationOptions object to be constructed and passed into the navigator.credentials.create() API. The only departure from the standard CreationOptions object being the new "possession" type:

```typescript
const possessionCreationOptions: PublicKeyCredentialCreationOptions = {
  rp: {
    name: "My RP",
    id: "example.com",
  },
  challenge: serverRes.challenge,
  user: {
    id,
    name,
    displayName,
  },
  pubKeyCredParams: [
    {
      type: "possession",
      alg,
    },
  ],
  timeout,
};

const possessionCred: PublicKeyCredential = await navigator.credentials.create({
  possession: possessionCreationOptions,
});
// Send the created credential to the server to verify and store
```

Above would require the navigator.credentials.create() API to be updated to generate a WebCrypto public-private key pair and store it securely, when type = "possession" is used:

```typescript
window.crypto.subtle
  .generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    false,
    ["sign", "verify"]
  )
  .then((key: CryptoKey) => {
    // Store CryptoKey object internally
  });
```

**Possession Credential Authentication**

Similarly, authentication will rely on a PublicKeyCredentialRequestOptions object to be constructed and passed into the navigator.credentials.get() API. The only departure from the standard RequestOptions object being the new "possession" type under "allowCredentials":

```typescript
const possessionRequestOptions: PublicKeyCredentialRequestOptions = {
  rpId: "example.com",
  challenge: serverRes.challenge,
  allowCredentials: [
    {
      type: "possession",
      id: serverRes.allowCredentials[0].id,
    },
  ],
  timeout,
};

const possessionCred: PublicKeyCredential = await navigator.credentials.get({ possession: possessionRequestOptions });
// Send the credential response to the server to verify
```

Above would require the navigator.credentials.get() API to be updated to retrieve the stored CryptoKey and sign the supplied challenge when type = "possession":

```typescript
window.crypto.subtle
  .sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    privateKey, //Would have been referenced using "allowCredentials" as specified in PublicKeyCredentialRequestOptions
    challengeToSign // Specified in PublicKeyCredentialRequestOptions
  )
  .then((signature) => {
    // Return the signedData as part of standard Credential
  })
  .catch((err) => {
    console.error(err);
  });
```

The possession credential should also be supported by Secure Payment Confirmation (SPC) to enable 1-click authentication during 3DS payment flows:

**SPC Registration**

Adapted from [SPC](https://github.com/rsolomakhin/secure-payment-confirmation#creating-a-credential):

```typescript
const securePaymentConfirmationCredentialCreationOptions = {
  instrument: {
    displayName: "Mastercard····4444",
    icon: "icon.png",
  },
  existingCredential: {
    type: "possession",
    id: Uint8Array.from(credentialId, (c) => c.charCodeAt(0)),
  },
  challenge,
  rp,
  publicKeyParams,
  timeout,
};

// Bind |instrument| to |credentialId|, or create a new credential if |credentialId| doesn't exist.
const credential = await navigator.credentials.create({
  payment: securePaymentCredentialCreationOptions,
});
```

An existing PublicKeyCredential with type "possession" could also be bound to SPC, as [described](https://github.com/rsolomakhin/secure-payment-confirmation#future-register-an-existing-publickeycredential-for-secure-payment-confirmation).

**SPC Authentication**

If the request was part of a user action, the possession credential can be queried through navigator.credentials.get() to perform a 1-click authentication:

```typescript
const possessionCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
  challenge,
  allowCredentials: [
    {
      id: Uint8Array.from(credentialId, (c) => c.charCodeAt(0)),
      type,
      transports,
    },
  ],
  timeout,
};

const credential = await navigator.credentials.get({
  publicKey: publicKeyCredentialRequestOptions,
});
```

A payment can also be authenticated in the same manner as [SPC](https://github.com/rsolomakhin/secure-payment-confirmation#authenticating-a-payment). Internally the possession credential can be used, which will determine what UI is presented to the customer:

```typescript
const securePaymentConfirmationRequest = {
  action: 'authenticate',
  credentialIds: Uint8Array.from(credentialId, (c) => c.charCodeAt(0)),
  networkData,
  timeout,
  fallbackUrl: "https://fallback.example/url"
};

const request = new PaymentRequest(
  [{supportedMethods: 'secure-payment-confirmation',
    data: securePaymentConfirmationRequest
  }],
  {total: {label: 'total', amount: {currency: 'USD', value: '20.00'}}});
const response = await request.show();
await response.complete('success');

// Merchant validates |response.challenge| and sends |response| to the issuer for authentication.
```

## Existing Proposals & Standards

There are a few existing industry proposals or standards that have been evaluated to assess their applicability to this proposal:

### [TrustToken](https://github.com/WICG/trust-token-api)

Although the cryptographic proof that trust tokens offer could be of value during a 3DS flow, the fact that they are designed to be used anonymously would not make them a good fit. This proposal covers 1st and 3rd party use-cases whereas trust tokens does not seem to have tangible 1st party applications. The fact that no user consent is required, is also not optimal.

### [Browser Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

Changes in the way browsers and users view web privacy has heavily impacted how cookies are used to track users around the web. Apple's Safari has already blocked the use of accessing cookies in a 3rd party context by default and Chrome has pledged to do the same. Additionally, cookies do not natively provide cryptographic functionality to sign payloads. Cookies are therefore not a viable option for these use-cases as it would not offer sufficient proof in a 3rd party context.

### [WebID](https://github.com/WICG/WebID)

WebID would allow signing in with an existing token when revisiting a resource, which does not fit the 3DS use-case which requires a challenge every time. This proposal aims to enhance the offering of the Relying Party (RP) by decreasing friction on the customer during this authentication events.

## Privacy & Security

Similar to WebAuthn credentials, the possession credential should also adopt a same-origin policy. While the User Presence gesture is core to the WebAuthn specification, the possession credential does not require this. The intention is to address this by requiring a user gesture inside the DOM before the `navigator.credentials.get()` operation can be fulfilled.

Furthermore, the same privacy considerations for WebAuthn are also applicable to this proposal. With regards to the key material, the WebCrypto generated key should be non-extractable and stored in the most secure storage that is available on the platform.

## Acknowledgements

Contributors:

- Adrian Hope-Bailie (Coil)​
- Arno van der Merwe (Entersekt)​
- Chris Dee (FIS Worldpay)​
- Danyao Wang (Google)​
- Erhard Brand (Entersekt)​
- Gerhard Oosthuizen (Entersekt)
- Ian Jacobs (W3C)​
- Rouslan Solomakhin (Google)​
