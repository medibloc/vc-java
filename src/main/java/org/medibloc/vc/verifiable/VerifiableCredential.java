package org.medibloc.vc.verifiable;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.model.Credential;
import org.medibloc.vc.verifiable.jwt.JwtVerifiableCredential;

import java.io.IOException;
import java.security.PublicKey;

@JsonDeserialize(using = VerifiableCredential.JsonDeserializer.class)
public interface VerifiableCredential {
    public Credential verify(PublicKey publicKey) throws VerifiableCredentialException;
    public String serialize();

    public class JsonDeserializer extends StdDeserializer<VerifiableCredential> {
        public JsonDeserializer() {
            this(null);
        }

        public JsonDeserializer(Class<?> vc) {
            super(vc);
        }

        @Override
        public VerifiableCredential deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
            JsonNode node = jsonParser.getCodec().readTree(jsonParser);
            if (node.isTextual()) {
                return new JwtVerifiableCredential(node.asText());
            }
            throw new IOException("unexpected value type: " + node.getNodeType());
        }
    }
}
