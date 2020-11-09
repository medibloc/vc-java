package org.medibloc.vc.verifiable;

import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Presentation;

import java.security.PublicKey;

public interface VerifiablePresentation {
    public Presentation verify(PublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();
}
