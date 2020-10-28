package org.medibloc.vc.verifiable;

import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;

import java.security.interfaces.ECPublicKey;

public interface VerifiableCredential {
    public Credential verify(ECPublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();
}
