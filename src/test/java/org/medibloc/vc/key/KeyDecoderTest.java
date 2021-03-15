package org.medibloc.vc.key;

import org.junit.Test;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.model.CredentialTest;
import org.medibloc.vc.verifiable.jwt.JwtVerifiableCredential;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeyDecoderTest {
    @Test
    public void decodeECKeyPair() throws InvalidKeySpecException, NoSuchAlgorithmException, ParseException, VerifiableCredentialException, MalformedURLException {
        Curve curve = Curve.SECP256K1;
        BigInteger priv = new BigInteger("8923338450195771520596999525524889973125454983673100838052553510113549826742");
        BigInteger x = new BigInteger("105928009891776317316312274395113443438472610508122053906576288971722796908538");
        BigInteger y = new BigInteger("13550149016935881183784944281356849764043559558946577069999526461962583096704");

        ECPrivateKey privateKey = KeyDecoder.ecPrivateKey(priv, curve);
        ECPublicKey publicKey = KeyDecoder.ecPublicKey(x, y, curve);

        assertKeyPair(privateKey, publicKey);
    }

    private void assertKeyPair(ECPrivateKey privateKey, ECPublicKey publicKey) throws ParseException, VerifiableCredentialException, MalformedURLException {
        Credential credential = CredentialTest.buildCredential();
        JwtVerifiableCredential vc = new JwtVerifiableCredential(
                credential, "ES256K", credential.getIssuer().getId() + "#key1", privateKey
        );
        assertNotNull(vc);
        assertEquals(credential, vc.verify(publicKey));
    }
}
