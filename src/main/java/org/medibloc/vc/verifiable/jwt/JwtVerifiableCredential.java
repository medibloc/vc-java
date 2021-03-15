package org.medibloc.vc.verifiable.jwt;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialSubject;
import org.medibloc.vc.model.Issuer;
import org.medibloc.vc.verifiable.VerifiableCredential;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY;
import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED;

/**
 * A verifiable credential in the form of external proof using JWT.
 * See https://www.w3.org/TR/vc-data-model/#proofs-signatures.
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class JwtVerifiableCredential extends JwtVerifiable implements VerifiableCredential {
    public JwtVerifiableCredential(Credential credential, String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
        super(jwsAlgo, keyId, privateKey, encode(credential));
    }

    public JwtVerifiableCredential(String jwt) {
        super(jwt);
    }

    @Override
    public Credential getCredential() throws VerifiableCredentialException {
        return decode(super.getJwtClaimsSet());
    }

    @Override
    public void verify(ECPublicKey publicKey) throws VerifiableCredentialException {
        super.verifyJwt(publicKey);
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VC = "vc";
    private static final String JWT_CLAIM_NAME_ISSUER = "issuer";  // for extra infos of the issuer

    /**
     * Encode a credential to a JWT payload, as described at https://www.w3.org/TR/vc-data-model/#jwt-encoding
     */
    private static JWTClaimsSet encode(Credential credential) {

        // Set JWT registered claims (iss, exp, ...)
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(credential.getIssuer().getId())
                .notBeforeTime(credential.getIssuanceDate());
        if (credential.getCredentialSubject().getId() != null) {
            builder.subject(credential.getCredentialSubject().getId());
        }
        if (credential.getExpirationDate() != null) {
            builder.expirationTime(credential.getExpirationDate());
        }
        if (credential.getId() != null) {
            builder.jwtID(credential.getId().toString());
        }

        // Set JWT private claims
        builder.claim(JWT_CLAIM_NAME_VC, VcClaim.from(credential).toMap());
        builder.claim(JWT_CLAIM_NAME_ISSUER, credential.getIssuer().getExtras());

        return builder.build();
    }

    /**
     * Decodes a JWT payload to a {@link Credential}, as described at https://www.w3.org/TR/vc-data-model/#jwt-decoding.
     */
    private static Credential decode(JWTClaimsSet claims) throws VerifiableCredentialException {
        try {
            VcClaim vcClaim = VcClaim.fromMap(claims.getJSONObjectClaim(JWT_CLAIM_NAME_VC));
            Map<String, Object> issuerExtras = claims.getJSONObjectClaim(JWT_CLAIM_NAME_ISSUER);

            Credential.CredentialBuilder builder =  Credential.builder()
                    .contexts(vcClaim.getContexts())
                    .types(vcClaim.getTypes())
                    .credentialSubject(new CredentialSubject(claims.getSubject(), vcClaim.getCredentialSubjectClaims()))
                    .issuer(new Issuer(claims.getIssuer(), issuerExtras))
                    .issuanceDate(claims.getNotBeforeTime());

            if (claims.getExpirationTime() != null) {
                builder = builder.expirationDate(claims.getExpirationTime());
            }
            if (claims.getJWTID() != null) {
                builder = builder.id(new URL(claims.getJWTID()));
            }

            return builder.build();
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    @AllArgsConstructor
    @Getter
    @EqualsAndHashCode
    @ToString
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyOrder(alphabetic = true)
    public static class VcClaim {
        @JsonProperty(Credential.JSON_PROP_CONTEXTS)
        @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
        private final List<String> contexts;
        @JsonProperty(Credential.JSON_PROP_TYPES)
        @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
        private final List<String> types;
        @JsonProperty(Credential.JSON_PROP_CRED_SUB)
        private final Map<String, Object> credentialSubjectClaims;

        // only for JSON deserialization
        public VcClaim() {
            this(null, null, null);
        }

        static VcClaim from(Credential credential) {
            return new VcClaim(credential.getContexts(), credential.getTypes(), credential.getCredentialSubject().getClaims());
        }

        static VcClaim fromMap(Map<String, Object> map) {
            return new ObjectMapper().convertValue(map, VcClaim.class);
        }

        public Map<String, Object> toMap() {
            return new ObjectMapper().convertValue(this, new TypeReference<Map<String, Object>>() {});
        }
    }
}
