package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;

import java.net.URL;
import java.util.List;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY;
import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED;

/**
 * Represents a presentation defined at https://www.w3.org/TR/vc-data-model/#presentations-0.
 * Note that this class doesn't contain any <a href="https://www.w3.org/TR/vc-data-model/#proofs-signatures">proof</a>.
 * This class can be a source of {@link VerifiablePresentation} which contains proofs.
 */
@Builder
@Getter
@EqualsAndHashCode
@ToString
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Presentation {
    @NonNull
    @JsonProperty(JSON_PROP_CONTEXTS)
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> contexts;
    private final URL id;
    @NonNull
    @JsonProperty(JSON_PROP_TYPES)
    @JsonFormat(with = {ACCEPT_SINGLE_VALUE_AS_ARRAY, WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
    private final List<String> types;
    @NonNull
    @JsonProperty(JSON_PROP_VERIFIABLE_CREDS)
    private final List<VerifiableCredential> verifiableCredentials;
    @NonNull
    private final String holder;  //TODO: type

    static final String JSON_PROP_CONTEXTS = "@context";
    static final String JSON_PROP_TYPES = "type";
    static final String JSON_PROP_VERIFIABLE_CREDS = "verifiableCredential";

    /**
     * Overrides the parts of the Lombok default builder.
     */
    static class PresentationBuilder {
        private List<String> contexts;
        private List<String> types;

        static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        static final String DEFAULT_TYPE = "VerifiablePresentation";

        /**
         * Validate the contexts
         */
        PresentationBuilder contexts(List<String> contexts) throws VerifiableCredentialException {
            Utils.assertNotNull(contexts, "contexts must not be null");
            if (!contexts.contains(DEFAULT_CONTEXT)) {
                throw new VerifiableCredentialException("contexts must contain the default context: " + DEFAULT_CONTEXT);
            }
            this.contexts = contexts;
            return this;
        }

        /**
         * Validate the types
         */
        PresentationBuilder types(List<String> types) throws VerifiableCredentialException {
            Utils.assertNotNull(types, "types must not be null");
            if (!types.contains(DEFAULT_TYPE)) {
                throw new VerifiableCredentialException("types must contain the default type: " + DEFAULT_TYPE);
            }
            this.types = types;
            return this;
        }
    }

    public String toJson() throws VerifiableCredentialException {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new VerifiableCredentialException(e);
        }
    }
}
