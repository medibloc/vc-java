package org.medibloc.vc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.Test;

import java.net.MalformedURLException;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiablePresentationTest {
    @Test
    public void createAndVerify() throws MalformedURLException, JOSEException, VerifiableCredentialException, ParseException {
        Presentation presentation = PresentationTest.buildPresentation();
        ECKey key = TestUtils.generateECKey(presentation.getHolder() + "#key1");

        JwtVerifiablePresentation vp = JwtVerifiablePresentation.create(
                presentation, "ES256K", key.getKeyID(), key.toECPrivateKey()
        );
        assertNotNull(vp);

        System.out.println(vp.serialize());

        assertEquals(presentation, vp.verify(key.toECPublicKey()));
        assertEquals(vp.getJwt(), vp.serialize());
    }
}
