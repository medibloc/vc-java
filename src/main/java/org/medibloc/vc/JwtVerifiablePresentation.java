package org.medibloc.vc;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

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
        return decode(verifyJwt(publicKey));
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
