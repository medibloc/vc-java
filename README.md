# Verifiable Credential SDK in Java 

This SDK is for creating/verifying W3C Verifiable Credentials and Presentations.
The behavior is compatible with the [Typescript SDK](https://github.com/decentralized-identity/did-jwt-vc) written by [DIF](https://identity.foundation).

## Features

- Creating/Verifying W3C Verifiable Credentials using JWT
- Creating/Verifying W3C Verifiable Presentation using JWT

Currently, only [external proof](https://www.w3.org/TR/vc-data-model/#proofs-signatures) using JWT is supported.
The embedded proof, such as a Linked Data Signature, would be supported in the future.

For more details, please see [Usages](#usage).

## Installation

TBD

## Usage

### Creating a Verifiable Credential

```java
import java.security.PrivateKey;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialSubject;
import org.medibloc.vc.model.Issuer;
import org.medibloc.vc.verifiable.VerifiableCredential;
import org.medibloc.vc.verifiable.jwt.JwtVerifiableCredential;

// Prepare a Issuer object
Issuer issuer = new Issuer("did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm");
issuer.addExtra("name", "Example University");  // You can add any extra info

// Prepare a CredentialSubject object
// The 'id' is optional. If you don't have an ID, you can use the default constructor.
CredentialSubject credentialSubject = new CredentialSubject("did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
// Claims can be set as key-values.
credentialSubject.addClaim("degree", new HashMap<String, Object>() {{
    put("type", "BachelorDegree");
    put("name", "Bachelor of Science and Arts");
}});

// Create a Credential which doesn't have any proof.
Credential credential = Credential.builder()
        .contexts(Arrays.asList("https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"))
        .types(Arrays.asList("VerifiableCredential", "UniversityDegreeCredential"))
        .id(new URL("http://example.edu/credentials/3732"))
        .issuer(issuer)
        .issuanceDate(new Date())
        .credentialSubject(credentialSubject)
        .build();

System.out.println(credential.toJson());
// {"@context":...,"credentialSubject":...}

// Create a VerifiableCredential using a key pair
// Currently, only external proof (JWT) is supported.
// This example assumes that you already have a private key.
PrivateKey privateKey = ...;

VerifiableCredential vc = new JwtVerifiableCredential(
        credential,
        "ES256K",
        "did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm#key1",
        privateKey
);

System.out.println(vc.serialize());
// eyJraWQiOiJkaWQ6cGFuYWNlYTo3UHJkNzRyeTF......
}
```

### Verifying a Verifiable Credential

```java
import java.security.PublicKey;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.verifiable.VerifiableCredential;

// This example assumes that you already have a public key.
// In the future, we will introduce the feature that resolves a public key from a DID document.
VerifiableCredential vc = ...;
PublicKey publicKey = ...;

Credential credential = vc.verify(publicKey);
```

### Creating a Verifiable Presentation

```java
import java.security.PrivateKey;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.verifiable.VerifiablePresentation;

Presentation presentation = Presentation.builder()
        .contexts(Arrays.asList("https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"))
        .types(Arrays.asList("VerifiablePresentation", "CredentialManagerPresentation"))
        .id(new URL("http://example.edu/presentations/1234"))
        .verifiableCredentials(Collections.singletonList(vc))
        .holder("did:panacea:nZqL3ny7aR7Cg46Jct87gk8azVgUmamVbJ7Prd74ry1U")
        .build();

System.out.println(credential.toJson());
// {"@context":...}
    
PrivateKey privateKey = ...;
VerifiablePresentation vp = new JwtVerifiablePresentation(
    presentation,
    "ES256K",
    "did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm#key1",
    privateKey
);

System.out.println(vc.serialize());
// eyJraWQiOiJkaWQ6cGFuYWNlYTo3UHJkNzRyeTF......
}
```

### Verifying a Verifiable Presentation

```java
import java.security.PublicKey;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.verifiable.VerifiablePresentation;

// This example assumes that you already have a public key.
// In the future, we will introduce the feature that resolves a public key from a DID document.
VerifiablePresentation vp = ...;
PublicKey publicKey = ...;

Presentation presentation = vp.verify(publicKey);
```
