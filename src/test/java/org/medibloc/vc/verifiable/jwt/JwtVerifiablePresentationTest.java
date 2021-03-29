package org.medibloc.vc.verifiable.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;
import org.medibloc.vc.model.PresentationTest;

import java.net.MalformedURLException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiablePresentationTest {
    @Test
    public void createAndVerify() throws MalformedURLException, VerifiableCredentialException, JOSEException {
        Presentation presentation = PresentationTest.buildPresentation();
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1).generate();

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", presentation.getHolder() + "#key1", ecJWK.toECPrivateKey()
        );
        assertNotNull(vp);

        System.out.println(vp.serialize());

        assertEquals(presentation, vp.getPresentation());
        vp.verify(ecJWK.toECPublicKey(), presentation.getVerifier());
        assertEquals(vp.getJwt(), vp.serialize());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void verificationFailure() throws MalformedURLException, VerifiableCredentialException, JOSEException {
        Presentation presentation = PresentationTest.buildPresentation();
        ECKey ecJWK1 = new ECKeyGenerator(Curve.SECP256K1).generate();

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", presentation.getHolder() + "#key1", ecJWK1.toECPrivateKey()
        );

        ECKey ecJWK2 = new ECKeyGenerator(Curve.SECP256K1).generate();
        vp.verify(ecJWK2.toECPublicKey(), presentation.getVerifier());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void verifierVerificationFailure() throws MalformedURLException, VerifiableCredentialException, JOSEException {
        Presentation presentation = PresentationTest.buildPresentation();
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1).generate();

        JwtVerifiablePresentation vp = new JwtVerifiablePresentation(
                presentation, "ES256K", presentation.getHolder() + "#key1", ecJWK.toECPrivateKey()
        );

        vp.verify(ecJWK.toECPublicKey(), "wrong-verifier");
    }
}
