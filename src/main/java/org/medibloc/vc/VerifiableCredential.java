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
import com.nimbusds.jose.shaded.json.JSONObject;
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
@JsonInclude(JsonInclude.Include.NON_NULL)
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

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'hh:mm:ss'Z'";

    @AllArgsConstructor
    @Getter
    @EqualsAndHashCode
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonPropertyOrder(alphabetic = true)
    public static class Issuer {
        private final String id;
        private final String name;
    }

    /**
     * Returns an external proof (a serialized JWT) that wraps the contents of the {@link VerifiableCredential}.
     * @param jwsAlgo
     * @param keyId
     * @param privateKey
     * @return A serialized JWT
     * @throws VerifiableCredentialException
     */
    public String sign(String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
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

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VC = "vc";

    private JWTClaimsSet toJwtPayload() {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(this.issuer.getId())
                .notBeforeTime(this.issuanceDate);
        if (this.credentialSubject.containsKey("id")) {
            claimsSetBuilder.subject(this.credentialSubject.get("id").toString());
        }
        if (this.expirationDate != null) {
            claimsSetBuilder.expirationTime(this.expirationDate);
        }
        if (this.id != null) {
            claimsSetBuilder.jwtID(this.id.toString());
        }

        claimsSetBuilder.claim(JWT_CLAIM_NAME_VC, toJwtVcClaim());

        Map<String, Object> issuerObj = new HashMap<String, Object>();
        issuerObj.put("name", this.issuer.getName());
        claimsSetBuilder.claim("issuer", issuerObj);

        return claimsSetBuilder.build();
    }

    private static VerifiableCredential fromJwtPayload(JWTClaimsSet payload) throws VerifiableCredentialException {
        JSONObject issuerClaim = (JSONObject) payload.getClaim("issuer");


        JSONObject vcClaim = (JSONObject) payload.getClaim(JWT_CLAIM_NAME_VC);
        if (vcClaim == null) {
            throw new VerifiableCredentialException(String.format("The claim: %s is not found", JWT_CLAIM_NAME_VC));
        }

        try {
            return new VerifiableCredential(
                    parseList(vcClaim.get("@context")),
                    new URL(payload.getJWTID()),
                    parseList(vcClaim.get("type")),
                    new Issuer(payload.getIssuer(), (String) issuerClaim.get("name")),
                    parseMap(vcClaim.get("credentialSubject")),
                    payload.getNotBeforeTime(),
                    payload.getExpirationTime()
            );
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    private static List<String> parseList(Object obj) throws VerifiableCredentialException {
        if (obj == null) {
            return null;
        }

        if (obj instanceof String) {
            return Collections.singletonList((String) obj);
        } else if (obj instanceof JSONArray) {
            List<String> ret = new ArrayList<String>(((JSONArray) obj).size());
            for (Object o : (JSONArray) obj) {
                ret.add((String) o);
            }
            return ret;
        }

        throw new VerifiableCredentialException("unexpected object: " + obj);
    }

    private static Map<String, Object> parseMap(Object obj) throws VerifiableCredentialException {
        Object parsed = parse(obj);
        if (parsed instanceof Map) {
            return (Map<String, Object>) parsed;
        }
        throw new VerifiableCredentialException("invalid object: " + obj);
    }

    private static Object parse(Object obj) {
        if (obj == null) {
            return null;
        }

        if (obj instanceof JSONObject) {
            Map<String, Object> map = new HashMap<String, Object>(((JSONObject) obj).size());
            for (String key : ((JSONObject) obj).keySet()) {
                map.put(key, parse(((JSONObject) obj).get(key)));
            }
            return map;
        } else if (obj instanceof JSONArray) {
            List<Object> list = new ArrayList<Object>(((JSONArray) obj).size());
            for (Object elem : (JSONArray) obj) {
                list.add(parse(elem));
            }
            return list;
        }

        return obj;
    }

    /**
     * Generates a JWT claim that represents a Verifiable Credential
     * without some fields which are used for the JWT registered claims (iss, exp, ...).
     */
    private Map<String, Object> toJwtVcClaim() {
        Map<String, Object> claim = new HashMap<String, Object>();
        claim.put("@context", this.contexts.size() > 1 ? this.contexts : this.contexts.get(0));
        claim.put("type", this.types.size() > 1 ? this.types : this.types.get(0));
        claim.put("credentialSubject", this.credentialSubject);
        return claim;
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
