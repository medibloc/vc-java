package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.util.Date;

@Getter
@ToString
@JsonPropertyOrder(alphabetic = true)
public class Proof {
    private final Type type;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'hh:mm:ss'Z'")
    private final Date created;
    private final Purpose proofPurpose;
    private final String verificationMethod;
    private final String jws;

    public Proof(Type type, Purpose proofPurpose, String verificationMethod, String jws) {
        this.type = type;
        this.created = new Date();
        this.proofPurpose = proofPurpose;
        this.verificationMethod = verificationMethod;
        this.jws = jws;
    }

    @AllArgsConstructor
    @Getter
    public enum Type {
        RSA("RsaSignature2018"),
        ED25519("Ed25519Signature2018"),
        ES256K("EcdsaSecp256k1Signature2019");

        @JsonValue
        private final String value;
    }

    @AllArgsConstructor
    @Getter
    public enum Purpose {
        ASSERTION_METHOD("assertionMethod");

        @JsonValue
        private final String value;
    }
}
