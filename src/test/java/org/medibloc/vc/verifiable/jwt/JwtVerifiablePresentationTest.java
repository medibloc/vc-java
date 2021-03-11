package org.medibloc.vc.verifiable.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.model.PresentationTest;

import java.net.MalformedURLException;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiablePresentationTest {
    @Test
    public void createAndVerify() throws MalformedURLException, VerifiableCredentialException {
        Presentation presentation = PresentationTest.buildPresentation();
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256K);

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", presentation.getHolder() + "#key1", keyPair.getPrivate()
        );
        assertNotNull(vp);

        System.out.println(vp.serialize());

        assertEquals(presentation, vp.verify(keyPair.getPublic()));
        assertEquals(vp.getJwt(), vp.serialize());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void verificationFailure() throws MalformedURLException, VerifiableCredentialException {
        Presentation presentation = PresentationTest.buildPresentation();
        KeyPair keyPair1 = Keys.keyPairFor(SignatureAlgorithm.ES256K);

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", presentation.getHolder() + "#key1", keyPair1.getPrivate()
        );

        KeyPair keyPair2 = Keys.keyPairFor(SignatureAlgorithm.ES256K);
        vp.verify(keyPair2.getPublic());
    }
}
