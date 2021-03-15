package org.medibloc.vc.verifiable.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialTest;

import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JwtVerifiableCredentialTest {
    @Test
    public void createAndVerify() throws MalformedURLException, VerifiableCredentialException, ParseException, JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        Credential credential = CredentialTest.buildCredential();
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1).generate();

        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", credential.getIssuer().getId() + "#key1", ecJWK.toECPrivateKey()
        );
        assertNotNull(vc);

        assertEquals(credential, vc.verify(ecJWK.toECPublicKey()));
        assertEquals(vc.getJwt(), vc.serialize());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void createWithInvalidAlgo() throws MalformedURLException, VerifiableCredentialException, ParseException, JOSEException {
        Credential credential = CredentialTest.buildCredential();
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1).generate();


        new JwtVerifiableCredential(
                credential, "INVALID", credential.getIssuer().getId() + "#key1", ecJWK.toECPrivateKey()
        );
    }

    @Test(expected = VerifiableCredentialException.class)
    public void verificationFailure() throws ParseException, VerifiableCredentialException, MalformedURLException, JOSEException {
        Credential credential = CredentialTest.buildCredential();
        ECKey ecJWK1 = new ECKeyGenerator(Curve.SECP256K1).generate();

        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", credential.getIssuer().getId() + "#key1", ecJWK1.toECPrivateKey()
        );

        ECKey ecJWK2 = new ECKeyGenerator(Curve.SECP256K1).generate();
        vc.verify(ecJWK2.toECPublicKey());
    }
}
