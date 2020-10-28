package org.medibloc.vc;

import java.security.interfaces.ECPublicKey;

public interface VerifiablePresentation {
    public Presentation verify(ECPublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();
}
