package org.medibloc.vc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.*;

/**
 * A verifiable credential in the form of external proof using JWT.
 * See https://www.w3.org/TR/vc-data-model/#proofs-signatures.
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@EqualsAndHashCode
public class JwtVerifiableCredential implements VerifiableCredential {
    @NonNull
    private final String jwt;

    /**
     * Creates a {@link JwtVerifiableCredential} by signing on the credential using a EC private key.
     * @param credential A credential to be signed
     * @param jwsAlgo A JWS algorithm
     * @param keyId A JWT key ID
     * @param privateKey A EC private key for signing
     * @return A verifiable credential
     * @throws VerifiableCredentialException
     */
    public static JwtVerifiableCredential create(Credential credential, String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
        Utils.assertNotNull(credential, "credential must not be null");
        Utils.assertNotNull(jwsAlgo, "keyType must not be null");
        Utils.assertNotNull(keyId, "keyId must not be null");
        Utils.assertNotNull(privateKey, "privateKey must not be null");

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse(jwsAlgo)).keyID(keyId).build(),
                encode(credential)
        );

        try {
            signedJWT.sign(new ECDSASigner(privateKey));
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }

        return new JwtVerifiableCredential(signedJWT.serialize());
    }

    /**
     * Verifies a verifiable credential using a EC public key and returns a credential decoded.
     * @param publicKey A EC public key
     * @return A decoded credential
     * @throws VerifiableCredentialException
     */
    @Override
    public Credential verify(ECPublicKey publicKey) throws VerifiableCredentialException {
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

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VC = "vc";
    private static final String JWT_CLAIM_NAME_ISSUER = "issuer";  // for extra infos of the issuer

    /**
     * Encode a credential to a JWT payload, as described at https://www.w3.org/TR/vc-data-model/#jwt-encoding
     */
    private static JWTClaimsSet encode(Credential credential) {
        // Set JWT registered claims (iss, exp, ...)
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(credential.getIssuer().getId())
                .notBeforeTime(credential.getIssuanceDate());
        if (credential.getCredentialSubject().getId() != null) {
            claimsSetBuilder.subject(credential.getCredentialSubject().getId());
        }
        if (credential.getExpirationDate() != null) {
            claimsSetBuilder.expirationTime(credential.getExpirationDate());
        }
        if (credential.getId() != null) {
            claimsSetBuilder.jwtID(credential.getId().toString());
        }

        // Set JWT private claims
        claimsSetBuilder.claim(JWT_CLAIM_NAME_VC, toJwtVcClaim(credential));
        claimsSetBuilder.claim(JWT_CLAIM_NAME_ISSUER, credential.getIssuer().getExtras());

        return claimsSetBuilder.build();
    }

    /**
     * Generates a JWT claim that represents a Verifiable Credential
     * without some fields to be used for the JWT registered claims (iss, exp, ...).
     */
    private static Map<String, Object> toJwtVcClaim(Credential credential) {
        Map<String, Object> claim = new HashMap<String, Object>();
        claim.put(Credential.JSON_PROP_CONTEXTS, credential.getContexts().size() > 1 ? credential.getContexts() : credential.getContexts().get(0));
        claim.put(Credential.JSON_PROP_TYPES, credential.getTypes().size() > 1 ? credential.getTypes() : credential.getTypes().get(0));
        claim.put(Credential.JSON_PROP_CRED_SUB, credential.getCredentialSubject().getClaims());  // without the subject ID
        return claim;
    }

    /**
     * Decodes a JWT payload to a {@link Credential}, as described at https://www.w3.org/TR/vc-data-model/#jwt-decoding.
     */
    private static Credential decode(JWTClaimsSet payload) throws VerifiableCredentialException {
        try {
            Map<String, Object> vcClaim = payload.getJSONObjectClaim(JWT_CLAIM_NAME_VC);
            if (vcClaim == null) {
                throw new VerifiableCredentialException(String.format("The claim: %s is not found", JWT_CLAIM_NAME_VC));
            }

            return new Credential(
                    toStringList(vcClaim.get(Credential.JSON_PROP_CONTEXTS)),
                    new URL(payload.getJWTID()),
                    toStringList(vcClaim.get(Credential.JSON_PROP_TYPES)),
                    new Issuer(payload.getIssuer(), payload.getJSONObjectClaim(JWT_CLAIM_NAME_ISSUER)),
                    new CredentialSubject(payload.getSubject(), toMap(vcClaim.get(Credential.JSON_PROP_CRED_SUB))),
                    payload.getNotBeforeTime(),
                    payload.getExpirationTime()
            );
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    /**
     * Create a string list from an object parsed by Nimbus JOSE JWT library, if possible.
     * This methods expects the object is a {@link String} or a {@link com.nimbusds.jose.shaded.json.JSONArray} which extends {@link ArrayList}.
     */
    private static List<String> toStringList(Object obj) throws VerifiableCredentialException {
        if (obj == null) {
            return null;
        }

        if (obj instanceof String) {  // if obj is string, returns a list with a single element.
            return Collections.singletonList((String) obj);
        } else if (obj instanceof JSONArray) {
            List<String> ret = new ArrayList<String>(((JSONArray) obj).size());
            for (Object o : (JSONArray) obj) {
                if (o instanceof String) {
                    ret.add((String) o);
                } else {
                    throw new VerifiableCredentialException("list contains a non-string object: " + o);
                }
            }
            return ret;
        }

        throw new VerifiableCredentialException("unexpected object: " + obj);
    }

    /**
     * Create a <code>Map<String, Object></code> from an object parsed by Nimbus JOSE JWT library, if possible.
     * This method expects the object is a {@link com.nimbusds.jose.shaded.json.JSONObject} which extends {@link HashMap}.
     */
    private static Map<String, Object> toMap(Object obj) throws VerifiableCredentialException {
        if (obj == null) {
            return null;
        }

        if (obj instanceof Map) {
            Map<String, Object> map = new HashMap<String, Object>();
            for (Map.Entry<?,?> entry : ((Map<?, ?>) obj).entrySet()) {
                if (entry.getKey() instanceof String) {
                    map.put((String) entry.getKey(), entry.getValue());
                } else {
                    throw new VerifiableCredentialException("key is not a string");
                }
            }
            return map;
        }

        throw new VerifiableCredentialException("object is not a map");
    }
}
