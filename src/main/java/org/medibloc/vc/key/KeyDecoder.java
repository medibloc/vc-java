package org.medibloc.vc.key;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class KeyDecoder {
    private static final String KEY_FACTORY_ALGO = "EC";

    public static ECPrivateKey ecPrivateKey(BigInteger bigInteger, Curve curve) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECPrivateKeySpec spec = new ECPrivateKeySpec(bigInteger, curve.toJwkCurve().toECParameterSpec());
        return (ECPrivateKey) KeyFactory.getInstance(KEY_FACTORY_ALGO).generatePrivate(spec);
    }

    public static ECPublicKey ecPublicKey(BigInteger x, BigInteger y, Curve curve) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECPoint point = new ECPoint(x, y);
        ECPublicKeySpec spec = new ECPublicKeySpec(point, curve.toJwkCurve().toECParameterSpec());
        return (ECPublicKey) KeyFactory.getInstance(KEY_FACTORY_ALGO).generatePublic(spec);
    }
}
