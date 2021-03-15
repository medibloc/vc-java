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
    @JsonValue
    @NonNull
    private final String jwt;

    JwtVerifiable(String algo, String keyId, ECPrivateKey privateKey, JWTClaimsSet jwtClaimsSet) throws VerifiableCredentialException {
        Assert.notNull(algo, "keyType must not be null");
        Assert.notNull(keyId, "keyId must not be null");
        Assert.notNull(privateKey, "privateKey must not be null");
        Assert.notNull(jwtClaimsSet, "jwtClaimsSet must not be null");

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algo)).keyID(keyId).build();
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        try {
            jwt.sign(new ECDSASigner(privateKey));
            this.jwt = jwt.serialize();
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    JWTClaimsSet verifyJwt(ECPublicKey publicKey) throws VerifiableCredentialException {
        try {
            SignedJWT jwt = SignedJWT.parse(this.jwt);
            if (!jwt.verify(new ECDSAVerifier(publicKey))) {
                throw new VerifiableCredentialException("JWT verification failed");
            }
            return jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    public String serialize() {
        return this.jwt;
    }
}
