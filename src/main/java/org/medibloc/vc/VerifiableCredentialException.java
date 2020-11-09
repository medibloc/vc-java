package org.medibloc.vc;

public class VerifiableCredentialException extends Exception {
    public VerifiableCredentialException(Exception e) {
        super(e);
    }

    public VerifiableCredentialException(String message) {
        super(message);
    }
}
