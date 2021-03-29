package org.medibloc.vc.verifiable;

import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;

import java.security.interfaces.ECPublicKey;

public interface VerifiablePresentation {
    public Presentation getPresentation() throws VerifiableCredentialException;
    public void verify(ECPublicKey publicKey, String nonce) throws VerifiableCredentialException;
    public String getKeyId() throws VerifiableCredentialException;
    public String serialize();
}
