package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.*;

/**
 * A verifiable presentation in the form of external proof using JWT.
 * See https://www.w3.org/TR/vc-data-model/#proofs-signatures.
 */
@AllArgsConstructor
@Getter
@EqualsAndHashCode
public class JwtVerifiablePresentation implements VerifiablePresentation {
    @NonNull
    @JsonValue
    private final String jwt;

    /**
     * Creates a {@link JwtVerifiablePresentation} by signing on the presentation using a EC private key.
     * @param presentation A presentation to be signed
     * @param jwsAlgo A JWS algorithm
     * @param keyId A JWT key ID
     * @param privateKey A EC private key for signing
     * @return A verifiable presentation
     * @throws VerifiableCredentialException
     */
    public static JwtVerifiablePresentation create(Presentation presentation, String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
        Utils.assertNotNull(presentation, "presentation must not be null");
        Utils.assertNotNull(jwsAlgo, "keyType must not be null");
        Utils.assertNotNull(keyId, "keyId must not be null");
        Utils.assertNotNull(privateKey, "privateKey must not be null");

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse(jwsAlgo)).keyID(keyId).build(),
                encode(presentation)
        );

        try {
            signedJWT.sign(new ECDSASigner(privateKey));
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }

        return new JwtVerifiablePresentation(signedJWT.serialize());
    }

    /**
     * Verifies a verifiable presentation using a EC public key and returns a credential decoded.
     * @param publicKey A EC public key
     * @return A decoded presentation
     * @throws VerifiableCredentialException
     */
    @Override
    public Presentation verify(ECPublicKey publicKey) throws VerifiableCredentialException {
        Utils.assertNotNull(publicKey, "publicKey must not be null");

        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);
            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw new VerifiableCredentialException("verification failure");
            }
            return decode(signedJWT.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    @Override
    public String serialize() {
        return this.jwt;
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VP = "vp";

    /**
     * Encode a presentation to a JWT payload.
     */
    private static JWTClaimsSet encode(Presentation presentation) throws VerifiableCredentialException {
        // Set JWT registered claims (iss, exp, ...)
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(presentation.getHolder());
        if (presentation.getId() != null) {
            claimsSetBuilder.jwtID(presentation.getId().toString());
        }

        // Set JWT private claims
        claimsSetBuilder.claim(JWT_CLAIM_NAME_VP, toJwtVpClaim(presentation));

        return claimsSetBuilder.build();
    }

    /**
     * Generates a JWT claim that represents a Verifiable Presentation
     * without some fields to be used for the JWT registered claims (iss, exp, ...).
     */
    private static Map<String, Object> toJwtVpClaim(Presentation presentation) throws VerifiableCredentialException {
        Map<String, Object> claim = new HashMap<String, Object>();
        claim.put(Presentation.JSON_PROP_CONTEXTS, Utils.simplifyList(presentation.getContexts()));
        claim.put(Presentation.JSON_PROP_TYPES, Utils.simplifyList(presentation.getTypes()));
        claim.put(Presentation.JSON_PROP_VERIFIABLE_CREDS, JwtObjectEncoder.fromVerifiableCredentials(presentation.getVerifiableCredentials()));
        return claim;
    }


    /**
     * Decodes a JWT payload to a {@link Presentation}.
     */
    private static Presentation decode(JWTClaimsSet payload) throws VerifiableCredentialException {
        try {
            Map<String, Object> vpClaim = payload.getJSONObjectClaim(JWT_CLAIM_NAME_VP);
            if (vpClaim == null) {
                throw new VerifiableCredentialException(String.format("The claim: %s is not found", JWT_CLAIM_NAME_VP));
            }

            return new Presentation(
                    JwtObjectDecoder.toList(vpClaim.get(Presentation.JSON_PROP_CONTEXTS), String.class),
                    new URL(payload.getJWTID()),
                    JwtObjectDecoder.toList(vpClaim.get(Presentation.JSON_PROP_TYPES), String.class),
                    JwtObjectDecoder.toVerifiableCredentials(vpClaim.get(Presentation.JSON_PROP_VERIFIABLE_CREDS)),
                    payload.getIssuer()
            );
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }


}
