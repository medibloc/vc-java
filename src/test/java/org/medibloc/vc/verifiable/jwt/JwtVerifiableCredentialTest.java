package org.medibloc.vc.verifiable.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialTest;

import java.net.MalformedURLException;
import java.security.KeyPair;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiableCredentialTest {
    @Test
    public void createAndVerify() throws MalformedURLException, VerifiableCredentialException, ParseException {
        Credential credential = CredentialTest.buildCredential();
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256K);

        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", credential.getIssuer().getId() + "#key1", keyPair.getPrivate()
        );
        assertNotNull(vc);

        assertEquals(credential, vc.verify(keyPair.getPublic()));
        assertEquals(vc.getJwt(), vc.serialize());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void createWithInvalidAlgo() throws MalformedURLException, VerifiableCredentialException, ParseException {
        Credential credential = CredentialTest.buildCredential();
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256K);

        new JwtVerifiableCredential(
                credential, "INVALID", credential.getIssuer().getId() + "#key1", keyPair.getPrivate()
        );
    }

    @Test(expected = VerifiableCredentialException.class)
    public void verificationFailure() throws ParseException, VerifiableCredentialException, MalformedURLException {
        Credential credential = CredentialTest.buildCredential();
        KeyPair keyPair1 = Keys.keyPairFor(SignatureAlgorithm.ES256K);

        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", credential.getIssuer().getId() + "#key1", keyPair1.getPrivate()
        );

        KeyPair keyPair2 = Keys.keyPairFor(SignatureAlgorithm.ES256K);
        vc.verify(keyPair2.getPublic());
    }
}
