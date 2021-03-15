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
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.verifiable.VerifiableCredential;
import org.medibloc.vc.verifiable.VerifiablePresentation;

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
 * A verifiable presentation in the form of external proof using JWT.
 * See https://www.w3.org/TR/vc-data-model/#proofs-signatures.
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class JwtVerifiablePresentation extends JwtVerifiable implements VerifiablePresentation {
    public JwtVerifiablePresentation(Presentation presentation, String jwsAlgo, String keyId, ECPrivateKey privateKey) throws VerifiableCredentialException {
        super(jwsAlgo, keyId, privateKey, encode(presentation));
    }

    public JwtVerifiablePresentation(String jwt) {
        super(jwt);
    }

    @Override
    public Presentation verify(ECPublicKey publicKey) throws VerifiableCredentialException {
        return decode(super.verifyJwt(publicKey));
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VP = "vp";

    /**
     * Encode a presentation to a JWT payload.
     */
    private static JWTClaimsSet encode(Presentation presentation) {
        // Set JWT registered claims (iss, exp, ...)
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().issuer(presentation.getHolder());
        if (presentation.getId() != null) {
            builder.jwtID(presentation.getId().toString());
        }

        // Set JWT private claims
        builder.claim(JWT_CLAIM_NAME_VP, VpClaim.from(presentation).toMap());

        return builder.build();
    }

    /**
     * Decodes a JWT payload to a {@link Presentation}.
     */
    private static Presentation decode(JWTClaimsSet claims) throws VerifiableCredentialException {
        try {
            VpClaim vpClaim = VpClaim.fromMap(claims.getJSONObjectClaim(JWT_CLAIM_NAME_VP));
            return Presentation.builder()
                    .contexts(vpClaim.getContexts())
                    .types(vpClaim.getTypes())
                    .verifiableCredentials(vpClaim.getVerifiableCredentials())
                    .holder(claims.getIssuer())
                    .id(new URL(claims.getJWTID()))
                    .build();
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
    public static class VpClaim {
        @JsonProperty(Presentation.JSON_PROP_CONTEXTS)
        @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
        private final List<String> contexts;
        @JsonProperty(Presentation.JSON_PROP_TYPES)
        @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
        private final List<String> types;
        @JsonProperty(Presentation.JSON_PROP_VERIFIABLE_CREDS)
        @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
        private final List<VerifiableCredential> verifiableCredentials;

        // only for JSON deserialization
        public VpClaim() {
            this(null, null, null);
        }

        static VpClaim from(Presentation presentation) {
            return new VpClaim(presentation.getContexts(), presentation.getTypes(), presentation.getVerifiableCredentials());
        }

        static VpClaim fromMap(Map<String, Object> map) {
            return new ObjectMapper().convertValue(map, VpClaim.class);
        }

        public Map<String, Object> toMap() {
            return new ObjectMapper().convertValue(this, new TypeReference<Map<String, Object>>() {});
        }
    }
}
