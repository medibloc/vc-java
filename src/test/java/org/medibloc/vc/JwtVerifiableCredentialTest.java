package org.medibloc.vc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.Test;

import java.net.MalformedURLException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiableCredentialTest {
    @Test
    public void createAndVerify() throws MalformedURLException, JOSEException, VerifiableCredentialException {
        Credential credential = CredentialTest.buildCredential();
        ECKey key = generateECKey(credential);

        JwtVerifiableCredential vc = JwtVerifiableCredential.create(
                credential, "ES256K", key.getKeyID(), key.toECPrivateKey()
        );
        assertNotNull(vc);

        assertEquals(credential, vc.verify(key.toECPublicKey()));
    }

    @Test(expected = VerifiableCredentialException.class)
    public void createWithInvalidAlgo() throws MalformedURLException, JOSEException, VerifiableCredentialException {
        Credential credential = CredentialTest.buildCredential();
        ECKey key = generateECKey(credential);

        JwtVerifiableCredential.create(
                credential, "INVALID", key.getKeyID(), key.toECPrivateKey()
        );
    }

    private static ECKey generateECKey(Credential credential) throws JOSEException {
        return new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(credential.getIssuer().getId() + "#key1") // in the format of the DID verification method
                .generate();
    }
}
