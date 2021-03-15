package org.medibloc.vc.verifiable;

import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;

import java.security.interfaces.ECPublicKey;

public interface VerifiablePresentation {
    public Presentation verify(ECPublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();
}
