package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.*;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY;
import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED;

@Builder
@Getter
@ToString
@JsonPropertyOrder(alphabetic = true)
public class VerifiableCredential {
    @NonNull
    @JsonProperty("@context")
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> contexts;
    private final URL id;
    @NonNull
    @JsonProperty("type")
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> types;
    @NonNull
    private final Issuer issuer;
    @NonNull
    private final Map<String, Object> credentialSubject;
    @NonNull
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date issuanceDate;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date expirationDate;
    @NonNull
    private final Proof proof;

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'hh:mm:ss'Z'";

    @AllArgsConstructor
    @Getter
    public static class Issuer {
        private final String id;
        private final String name;
    }

    /**
     * Overrides the parts of the Lombok default builder.
     */
    static class VerifiableCredentialBuilder {
        private List<String> contexts;
        private List<String> types;
        private Proof proof;

        private static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        private static final String DEFAULT_TYPE = "VerifiableCredential";
        private static final String JWT_FIELD_NAME_VC = "vc";

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

        /**
         * Generate a proof using a private key and data which has been provided to the {@link VerifiableCredentialBuilder}.
         */
        VerifiableCredentialBuilder proof(Proof.Type keyType, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
            Utils.assertNotNull(keyType, "keyType must not be null");
            Utils.assertNotNull(keyId, "keyId must not be null");
            Utils.assertNotNull(privateKey, "privateKey must not be null");

            this.proof = generateProof(this, keyType, keyId, privateKey);
            return this;
        }

        private static Proof generateProof(VerifiableCredentialBuilder builder, Proof.Type keyType, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
            Utils.assertNotNull(builder.contexts, "contexts must be set before proof");
            Utils.assertNotNull(builder.types, "types must be set before proof");
            Utils.assertNotNull(builder.issuer, "issuer must be set before proof");
            Utils.assertNotNull(builder.issuanceDate, "issuanceDate must be set before proof");
            Utils.assertNotNull(builder.credentialSubject, "credentialSubject must be set before proof");

            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                    .issuer(builder.issuer.getId())
                    .notBeforeTime(builder.issuanceDate);
            if (builder.credentialSubject.containsKey("id")) {
                claimsSetBuilder.subject(builder.credentialSubject.get("id").toString());
            }
            if (builder.expirationDate != null) {
                claimsSetBuilder.expirationTime(builder.expirationDate);
            }
            if (builder.id != null) {
                claimsSetBuilder.jwtID(builder.id.toString());
            }

            claimsSetBuilder.claim(JWT_FIELD_NAME_VC, generateJwtClaimVc(builder));

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(getJWSAlgorithm(keyType)).keyID(keyId).build(),
                    claimsSetBuilder.build()
            );

            try {
                jwt.sign(new ECDSASigner(privateKey));
            } catch (JOSEException e) {
                throw new VerifiableCredentialException(e);
            }

            return new Proof(keyType, Proof.Purpose.ASSERTION_METHOD, keyId, jwt.serialize());
        }

        /**
         * Generates a JWT claim that represents a Verifiable Credential
         * by removing some fields which are used for the JWT registered claims (iss, exp, ...).
         */
        private static Map<String, Object> generateJwtClaimVc(VerifiableCredentialBuilder builder) {
            Map<String, Object> claim = new HashMap<String, Object>();
            claim.put("@context", builder.contexts.size() > 1 ? builder.contexts : builder.contexts.get(0));
            claim.put("type", builder.types.size() > 1 ? builder.types : builder.types.get(0));
            claim.put("credentialSubject", builder.credentialSubject);
            return claim;
        }

        private static JWSAlgorithm getJWSAlgorithm(Proof.Type type) throws VerifiableCredentialException {
            switch (type) {
                case RSA:
                    return JWSAlgorithm.RS256;
                case ED25519:
                    return JWSAlgorithm.EdDSA;
                case ES256K:
                    return JWSAlgorithm.ES256K;
                default:
                    throw new VerifiableCredentialException("unsupported proof type: " + type);
            }
        }
    }
}
