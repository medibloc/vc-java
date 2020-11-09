package org.medibloc.vc.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.lang.Assert;
import org.medibloc.vc.verifiable.VerifiableCredential;
import org.medibloc.vc.verifiable.VerifiablePresentation;

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
@EqualsAndHashCode(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Presentation extends JsonSerializable {
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
    private final String holder;  //TODO: make sure about its type

    public static final String JSON_PROP_CONTEXTS = "@context";
    public static final String JSON_PROP_TYPES = "type";
    public static final String JSON_PROP_VERIFIABLE_CREDS = "verifiableCredential";

    /**
     * Overrides the parts of the Lombok default builder.
     */
    public static class PresentationBuilder {
        private List<String> contexts;
        private List<String> types;

        static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        static final String DEFAULT_TYPE = "VerifiablePresentation";

        /**
         * Validate the contexts
         */
        public PresentationBuilder contexts(List<String> contexts) throws VerifiableCredentialException {
            Assert.notNull(contexts, "contexts must not be null");
            if (!contexts.contains(DEFAULT_CONTEXT)) {
                throw new VerifiableCredentialException("contexts must contain the default context: " + DEFAULT_CONTEXT);
            }
            this.contexts = contexts;
            return this;
        }

        /**
         * Validate the types
         */
        public PresentationBuilder types(List<String> types) throws VerifiableCredentialException {
            Assert.notNull(types, "types must not be null");
            if (!types.contains(DEFAULT_TYPE)) {
                throw new VerifiableCredentialException("types must contain the default type: " + DEFAULT_TYPE);
            }
            this.types = types;
            return this;
        }
    }
}
