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
    public Credential verify(ECPublicKey publicKey) throws VerifiableCredentialException {
        return decode(verifyJwt(publicKey));
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
        claim.put(Credential.JSON_PROP_CONTEXTS, Utils.simplifyList(credential.getContexts()));
        claim.put(Credential.JSON_PROP_TYPES, Utils.simplifyList(credential.getTypes()));
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
                    JwtObjectDecoder.toList(vcClaim.get(Credential.JSON_PROP_CONTEXTS), String.class),
                    new URL(payload.getJWTID()),
                    JwtObjectDecoder.toList(vcClaim.get(Credential.JSON_PROP_TYPES), String.class),
                    new Issuer(payload.getIssuer(), payload.getJSONObjectClaim(JWT_CLAIM_NAME_ISSUER)),
                    new CredentialSubject(payload.getSubject(), JwtObjectDecoder.toMap(vcClaim.get(Credential.JSON_PROP_CRED_SUB), String.class)),
                    payload.getNotBeforeTime(),
                    payload.getExpirationTime()
            );
        } catch (MalformedURLException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }
}
