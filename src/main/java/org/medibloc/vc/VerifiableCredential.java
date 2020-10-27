package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
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

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY;
import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED;

@Builder
@Getter
@EqualsAndHashCode
@ToString
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class VerifiableCredential {
    @NonNull
    @JsonProperty(JSON_PROP_CONTEXTS)
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> contexts;
    private final URL id;
    @NonNull
    @JsonProperty(JSON_PROP_TYPES)
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> types;
    @NonNull
    private final Issuer issuer;
    @NonNull
    private final CredentialSubject credentialSubject;
    @NonNull
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date issuanceDate;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date expirationDate;

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'hh:mm:ss'Z'";
    private static final String JSON_PROP_CONTEXTS = "@context";
    private static final String JSON_PROP_TYPES = "type";
    private static final String JSON_PROP_CRED_SUB = "credentialSubject";

    /**
     * Returns an external proof (a serialized JWT) that wraps the contents of the {@link VerifiableCredential}.
     * @param jwsAlgo
     * @param keyId
     * @param privateKey
     * @return A serialized JWT
     * @throws VerifiableCredentialException
     */
    public String toJwt(String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
        Utils.assertNotNull(jwsAlgo, "keyType must not be null");
        Utils.assertNotNull(keyId, "keyId must not be null");
        Utils.assertNotNull(privateKey, "privateKey must not be null");

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.parse(jwsAlgo)).keyID(keyId).build(),
                toJwtPayload()
        );

        try {
            jwt.sign(new ECDSASigner(privateKey));
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }

        return jwt.serialize();
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VC = "vc";
    private static final String JWT_CLAIM_NAME_ISSUER = "issuer";  // for extra infos of the issuer

    /**
     * Generates a JWT payload from the object. This method fills JWT registered/private claims as described at
     * https://www.w3.org/TR/vc-data-model/#jwt-encoding
     * @return A JWT payload
     */
    private JWTClaimsSet toJwtPayload() {
        // Set JWT registered claims (iss, exp, ...)
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(this.issuer.getId())
                .notBeforeTime(this.issuanceDate);
        if (this.credentialSubject.getId() != null) {
            claimsSetBuilder.subject(this.credentialSubject.getId());
        }
        if (this.expirationDate != null) {
            claimsSetBuilder.expirationTime(this.expirationDate);
        }
        if (this.id != null) {
            claimsSetBuilder.jwtID(this.id.toString());
        }

        // Set JWT private claims
        claimsSetBuilder.claim(JWT_CLAIM_NAME_VC, toJwtVcClaim());
        claimsSetBuilder.claim(JWT_CLAIM_NAME_ISSUER, this.issuer.getExtras());

        return claimsSetBuilder.build();
    }

    /**
     * Generates a JWT claim that represents a Verifiable Credential
     * without some fields to be used for the JWT registered claims (iss, exp, ...).
     */
    private Map<String, Object> toJwtVcClaim() {
        Map<String, Object> claim = new HashMap<String, Object>();
        claim.put(JSON_PROP_CONTEXTS, this.contexts.size() > 1 ? this.contexts : this.contexts.get(0));
        claim.put(JSON_PROP_TYPES, this.types.size() > 1 ? this.types : this.types.get(0));
        claim.put(JSON_PROP_CRED_SUB, this.credentialSubject.getClaims());  // without the subject ID
        return claim;
    }

    /**
     * Creates a {@link VerifiableCredential} object by verifying JWT using a public key.
     * @param serializedJwt A serialized JWT string
     * @param publicKey A public key for the JWT verification
     * @return A VerifiableCredential
     * @throws VerifiableCredentialException Verification failure
     */
    public static VerifiableCredential fromJwt(String serializedJwt, ECPublicKey publicKey) throws VerifiableCredentialException {
        Utils.assertNotNull(serializedJwt, "serializedJwt must not be null");
        Utils.assertNotNull(publicKey, "publicKey must not be null");

        try {
            SignedJWT jwt = SignedJWT.parse(serializedJwt);
            if (!jwt.verify(new ECDSAVerifier(publicKey))) {
                throw new VerifiableCredentialException("verification failure");
            }
            return fromJwtPayload(jwt.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    /**
     * Converts a JWT payload into a {@link VerifiableCredential} as described at https://www.w3.org/TR/vc-data-model/#jwt-decoding.
     * @param payload A JWT payload
     * @return A VerifiableCredential
     * @throws VerifiableCredentialException The JWT payload is invalid
     */
    private static VerifiableCredential fromJwtPayload(JWTClaimsSet payload) throws VerifiableCredentialException {
        try {
            Map<String, Object> vcClaim = payload.getJSONObjectClaim(JWT_CLAIM_NAME_VC);
            if (vcClaim == null) {
                throw new VerifiableCredentialException(String.format("The claim: %s is not found", JWT_CLAIM_NAME_VC));
            }

            return new VerifiableCredential(
                    toStringList(vcClaim.get(JSON_PROP_CONTEXTS)),
                    new URL(payload.getJWTID()),
                    toStringList(vcClaim.get(JSON_PROP_TYPES)),
                    new Issuer(payload.getIssuer(), payload.getJSONObjectClaim(JWT_CLAIM_NAME_ISSUER)),
                    new CredentialSubject(payload.getSubject(), toMap(vcClaim.get(JSON_PROP_CRED_SUB))),
                    payload.getNotBeforeTime(),
                    payload.getExpirationTime()
            );
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

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

    /**
     * Overrides the parts of the Lombok default builder.
     */
    static class VerifiableCredentialBuilder {
        private List<String> contexts;
        private List<String> types;

        private static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        private static final String DEFAULT_TYPE = "VerifiableCredential";

        /**
         * Put the default context at the front of the context list provided.
         */
        VerifiableCredentialBuilder contexts(List<String> contexts) {
            Utils.assertNotNull(contexts, "contexts must not be null");

            this.contexts = new ArrayList<String>(1 + contexts.size());
            this.contexts.add(DEFAULT_CONTEXT);
            this.contexts.addAll(contexts);
            return this;
        }

        /**
         * Put the default type at the front of the type list provided.
         */
        VerifiableCredentialBuilder types(List<String> types) {
            Utils.assertNotNull(types, "types must not be null");

            this.types = new ArrayList<String>(1 + types.size());
            this.types.add(DEFAULT_TYPE);
            this.types.addAll(types);
            return this;
        }
    }
}
