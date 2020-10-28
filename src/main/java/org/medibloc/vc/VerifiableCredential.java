package org.medibloc.vc;

import java.security.interfaces.ECPublicKey;

public interface VerifiableCredential {
    public Credential verify(ECPublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();
}
