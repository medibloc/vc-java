# Verifiable Credential SDK in Java 

This SDK is for creating/verifying W3C Verifiable Credentials and Presentations.
The behavior is compatible with the [Typescript SDK](https://github.com/decentralized-identity/did-jwt-vc) written by [DIF](https://identity.foundation).

## Installation

TBD

## Usage

### Creating a Verifiable Credential

```java
import java.security.interfaces.ECPrivateKey;
import org.medibloc.vc.*;

class VCTest {
    @Test
    public void test() {
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
            .contexts(Collections.singletonList("https://www.w3.org/2018/credentials/examples/v1"))
            .types(Collections.singletonList("UniversityDegreeCredential"))
            .id(new URL("http://example.edu/credentials/3732"))
            .issuer(issuer)
            .issuanceDate(new Date())
            .credentialSubject(credentialSubject)
            .build();

        // Create a VerifiableCredential using ECKey
        // Currently, only external proof (JWT) is supported.
        // This example assumes that you already have a EC private key.
        ECPrivateKey privateKey = ...;
        VerifiableCredential vc = JwtVerifiableCredential.create(
            credential,
            "ES256K",
            "did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm#key1",
            privateKey
        );
    }
}
```

### Verifying a Verifiable Credential

```java
import java.security.interfaces.ECPublicKey;
import org.medibloc.vc.*;

class VCTest {
    @Test
    public void test() {
        // This example assumes that you already have a EC public key.
        // In the future, we will introduce the feature that resolves a public key from a DID document.
        VerifiableCredential vc = ...;
        ECPublicKey publicKey = ...;

        Credential credential = vc.verify(publicKey);
    }
}
```

### Creating a Verifiable Presentation

TBD

### Verifying a Verifiable Presentation

TBD
