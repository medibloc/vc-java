package org.medibloc.vc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.Test;

import java.net.MalformedURLException;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiableCredentialTest {
    @Test
    public void createAndVerify() throws MalformedURLException, JOSEException, VerifiableCredentialException, ParseException {
        Credential credential = CredentialTest.buildCredential();
        ECKey key = TestUtils.generateECKey(credential.getIssuer().getId() + "#key1");

        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", key.getKeyID(), key.toECPrivateKey()
        );
        assertNotNull(vc);

        assertEquals(credential, vc.verify(key.toECPublicKey()));
        assertEquals(vc.getJwt(), vc.serialize());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void createWithInvalidAlgo() throws MalformedURLException, JOSEException, VerifiableCredentialException, ParseException {
        Credential credential = CredentialTest.buildCredential();
        ECKey key = TestUtils.generateECKey(credential.getIssuer().getId() + "#key1");

        new JwtVerifiableCredential(
                credential, "INVALID", key.getKeyID(), key.toECPrivateKey()
        );
    }
}
