package org.medibloc.vc.verifiable.jwt;

import com.fasterxml.jackson.annotation.JsonValue;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.lang.Assert;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

@AllArgsConstructor
@Getter
@EqualsAndHashCode
class JwtVerifiable {
    // For preventing a holder (or a verifier) from impersonating the issuer (or the holder).
    // https://www.w3.org/TR/2019/REC-vc-data-model-20191119/#example-28-jwt-payload-of-a-jwt-based-verifiable-credential-using-jws-as-a-proof-non-normative
    private static final String JWT_CLAIM_NAME_NONCE = "nonce";

    @JsonValue
    @NonNull
    private final String jwt;

    JwtVerifiable(String algo, String keyId, ECPrivateKey privateKey, JWTClaimsSet.Builder jwtClaimsSetBuilder, String nonce) throws VerifiableCredentialException {
        Assert.notNull(algo, "keyType must not be null");
        Assert.notNull(keyId, "keyId must not be null");
        Assert.notNull(privateKey, "privateKey must not be null");
        Assert.notNull(jwtClaimsSetBuilder, "jwtClaimsSetBuilder must not be null");
        Assert.notNull(nonce, "nonce must not be null");

        jwtClaimsSetBuilder.claim(JWT_CLAIM_NAME_NONCE, nonce);

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algo)).keyID(keyId).build();
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        try {
            jwt.sign(new ECDSASigner(privateKey));
            this.jwt = jwt.serialize();
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    void verifyJwt(ECPublicKey publicKey, String nonce) throws VerifiableCredentialException {
        try {
            SignedJWT jwt = SignedJWT.parse(this.jwt);

            String nonceInJwt = (String) jwt.getJWTClaimsSet().getClaims().get(JWT_CLAIM_NAME_NONCE);
            if (nonceInJwt == null || !nonceInJwt.equals(nonce)) {
                throw new VerifiableCredentialException("JWT nonce doesn't match. Expected:" + nonce + ", Actual:" + nonceInJwt);
            }

            if (!jwt.verify(new ECDSAVerifier(publicKey))) {
                throw new VerifiableCredentialException("JWT verification failed");
            }
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    JWTClaimsSet getJwtClaimsSet() throws VerifiableCredentialException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    public String getKeyId() throws VerifiableCredentialException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);
            return signedJWT.getHeader().getKeyID();
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    public String serialize() {
        return this.jwt;
    }
}
