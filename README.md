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

For Gradle:
```gradle
repositories {
    maven {
        url = "https://maven.pkg.github.com/medibloc/vc-java"
        // GitHub Packages credentials
        credentials {
            username = System.getenv("GPR_USER")
            password = System.getenv("GPR_API_KEY")
        }
    }
    mavenCentral()
}

dependencies {
    implementation 'org.medibloc:vc-java:0.0.4'
}
```

## Usage

### Creating/Verifying a Verifiable Credential

[Sample](src/test/java/org/medibloc/vc/verifiable/jwt/JwtVerifiableCredentialTest.java)

### Creating/Verifying a Verifiable Presentation

[Sample](src/test/java/org/medibloc/vc/verifiable/jwt/JwtVerifiablePresentationTest.java)
