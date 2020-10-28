package org.medibloc.vc.verifiable.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.model.PresentationTest;

import java.net.MalformedURLException;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiablePresentationTest {
    @Test
    public void createAndVerify() throws MalformedURLException, JOSEException, VerifiableCredentialException, ParseException {
        Presentation presentation = PresentationTest.buildPresentation();
        ECKey key = TestUtils.generateECKey(presentation.getHolder() + "#key1");

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", key.getKeyID(), key.toECPrivateKey()
        );
        assertNotNull(vp);

        System.out.println(vp.serialize());

        assertEquals(presentation, vp.verify(key.toECPublicKey()));
        assertEquals(vp.getJwt(), vp.serialize());
    }
}
