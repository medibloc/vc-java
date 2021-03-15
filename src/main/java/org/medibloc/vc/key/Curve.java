package org.medibloc.vc.key;

public enum Curve {
    P_256("P-256"),
    SECP256K1("secp256k1"),
    P_384("P-384"),
    P_521("P-521"),
    Ed25519("Ed25519"),
    Ed448("Ed448"),
    X25519("X25519"),
    X448("X448"),
    ;

    private final String name;

    Curve(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    com.nimbusds.jose.jwk.Curve toJwkCurve() {
        return com.nimbusds.jose.jwk.Curve.parse(this.name);
    }
}
