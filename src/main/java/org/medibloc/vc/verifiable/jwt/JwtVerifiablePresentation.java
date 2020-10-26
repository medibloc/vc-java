package org.medibloc.vc.verifiable.jwt;

import com.fasterxml.jackson.annotation.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import lombok.*;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.verifiable.VerifiableCredential;
import org.medibloc.vc.verifiable.VerifiablePresentation;

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
 * A verifiable presentation in the form of external proof using JWT.
 * See https://www.w3.org/TR/vc-data-model/#proofs-signatures.
 */
@Getter
@EqualsAndHashCode(callSuper = true)
public class JwtVerifiablePresentation extends JwtVerifiable implements VerifiablePresentation {
    public JwtVerifiablePresentation(Presentation presentation, String jwsAlgo, String keyId, PrivateKey privateKey) throws VerifiableCredentialException {
        super(jwsAlgo, keyId, privateKey, encode(presentation));
    }

    public JwtVerifiablePresentation(String jws) {
        super(jws);
    }

    @Override
    public Presentation verify(PublicKey publicKey) throws VerifiableCredentialException {
        Map<String, Class> classMap = new HashMap<String, Class>();
        classMap.put(JWT_CLAIM_NAME_VP, VpClaim.class);
        return decode(super.verifyJwt(publicKey, classMap).getBody());
    }

    // https://www.w3.org/TR/vc-data-model/#json-web-token-extensions
    private static final String JWT_CLAIM_NAME_VP = "vp";

    /**
     * Encode a presentation to a JWT payload.
     */
    private static JwtBuilder encode(Presentation presentation) throws VerifiableCredentialException {
        // Set JWT registered claims (iss, exp, ...)
        JwtBuilder builder = Jwts.builder()
                .setIssuer(presentation.getHolder());
        if (presentation.getId() != null) {
            builder.setId(presentation.getId().toString());
        }

        // Set JWT private claims
        builder.claim(JWT_CLAIM_NAME_VP, VpClaim.from(presentation));

        return builder;
    }

    /**
     * Decodes a JWT payload to a {@link Presentation}.
     */
    private static Presentation decode(Claims claims) throws VerifiableCredentialException {
        VpClaim vpClaim = claims.get(JWT_CLAIM_NAME_VP, VpClaim.class);
        try {
            return Presentation.builder()
                    .contexts(vpClaim.getContexts())
                    .types(vpClaim.getTypes())
                    .verifiableCredentials(vpClaim.getVerifiableCredentials())
                    .holder(claims.getIssuer())
                    .id(new URL(claims.getId()))
                    .build();
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
    }
}
