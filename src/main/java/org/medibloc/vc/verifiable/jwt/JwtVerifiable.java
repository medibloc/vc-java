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
import org.medibloc.vc.common.Utils;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

@AllArgsConstructor
@Getter
@EqualsAndHashCode
class JwtVerifiable {
    @NonNull
    @JsonValue
    private final String jwt;

    JwtVerifiable(String algo, String keyId, ECPrivateKey privateKey, JWTClaimsSet claimsSet) throws VerifiableCredentialException {
        Utils.assertNotNull(algo, "keyType must not be null");
        Utils.assertNotNull(keyId, "keyId must not be null");
        Utils.assertNotNull(privateKey, "privateKey must not be null");
        Utils.assertNotNull(claimsSet, "claimsSet must not be null");

        try {
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.parse(algo)).keyID(keyId).build(),
                    claimsSet
            );
            signedJWT.sign(new ECDSASigner(privateKey));

            this.jwt = signedJWT.serialize();
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    JWTClaimsSet verifyJwt(ECPublicKey publicKey) throws VerifiableCredentialException {
        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);
            if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
                throw new VerifiableCredentialException("verification failure");
            }
            return signedJWT.getJWTClaimsSet();
        } catch (JOSEException e) {
            throw new VerifiableCredentialException(e);
        } catch (ParseException e) {
            throw new VerifiableCredentialException(e);
        }
    }

    public String serialize() {
        return this.jwt;
    }
}
