package org.medibloc.vc.verifiable.jwt;

import com.fasterxml.jackson.annotation.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import lombok.*;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialSubject;
import org.medibloc.vc.model.Issuer;
import org.medibloc.vc.verifiable.VerifiableCredential;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
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
    private static final Map<String, Class> classMap = new HashMap<String, Class>(){{
        put(JWT_CLAIM_NAME_VC, VcClaim.class);
        put(JWT_CLAIM_NAME_ISSUER, Issuer.Extras.class);
    }};

    public JwtVerifiableCredential(Credential credential, String jwsAlgo, String keyId, PrivateKey privateKey) throws VerifiableCredentialException {
        super(jwsAlgo, keyId, privateKey, encode(credential));
    }

    public JwtVerifiableCredential(String jws) {
        super(jws);
    }

    @Override
    public Credential verify(PublicKey publicKey) throws VerifiableCredentialException {
        return decode(super.verifyJwt(publicKey, this.classMap).getBody());
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VC = "vc";
    private static final String JWT_CLAIM_NAME_ISSUER = "issuer";  // for extra infos of the issuer

    /**
     * Encode a credential to a JWT payload, as described at https://www.w3.org/TR/vc-data-model/#jwt-encoding
     */
    private static JwtBuilder encode(Credential credential) {
        // Set JWT registered claims (iss, exp, ...)
        JwtBuilder builder = Jwts.builder()
                .setIssuer(credential.getIssuer().getId())
                .setNotBefore(credential.getIssuanceDate());
        if (credential.getCredentialSubject().getId() != null) {
            builder.setSubject(credential.getCredentialSubject().getId());
        }
        if (credential.getExpirationDate() != null) {
            builder.setExpiration(credential.getExpirationDate());
        }
        if (credential.getId() != null) {
            builder.setId(credential.getId().toString());
        }

        // Set JWT private claims
        builder.claim(JWT_CLAIM_NAME_VC, VcClaim.from(credential));
        builder.claim(JWT_CLAIM_NAME_ISSUER, credential.getIssuer().getExtras());

        return builder;
    }

    /**
     * Decodes a JWT payload to a {@link Credential}, as described at https://www.w3.org/TR/vc-data-model/#jwt-decoding.
     */
    private static Credential decode(Claims claims) throws VerifiableCredentialException {
        VcClaim vcClaim = claims.get(JWT_CLAIM_NAME_VC, VcClaim.class);
        Issuer.Extras issuerExtras = claims.get(JWT_CLAIM_NAME_ISSUER, Issuer.Extras.class);

        try {
            Credential.CredentialBuilder builder =  Credential.builder()
                    .contexts(vcClaim.getContexts())
                    .types(vcClaim.getTypes())
                    .credentialSubject(new CredentialSubject(claims.getSubject(), vcClaim.getCredentialSubjectClaims()))
                    .issuer(new Issuer(claims.getIssuer(), issuerExtras))
                    .issuanceDate(claims.getNotBefore());

            if (claims.getExpiration() != null) {
                builder = builder.expirationDate(claims.getExpiration());
            }
            if (claims.getId() != null) {
                builder = builder.id(new URL(claims.getId()));
            }

            return builder.build();
        } catch (MalformedURLException e) {
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
    }
}
