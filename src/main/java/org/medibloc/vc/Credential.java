package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY;
import static com.fasterxml.jackson.annotation.JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED;

/**
 * Represents a credential defined at https://www.w3.org/TR/vc-data-model/#credentials.
 * Note that this class doesn't contain any <a href="https://www.w3.org/TR/vc-data-model/#proofs-signatures">proof</a>.
 * This class can be a source of {@link VerifiableCredential} which contains proofs.
 */
@Builder
@Getter
@EqualsAndHashCode
@ToString
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Credential {
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
    private final Issuer issuer;
    @NonNull
    private final CredentialSubject credentialSubject;
    @NonNull
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date issuanceDate;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT)
    private final Date expirationDate;

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'hh:mm:ss'Z'";
    static final String JSON_PROP_CONTEXTS = "@context";
    static final String JSON_PROP_TYPES = "type";
    static final String JSON_PROP_CRED_SUB = "credentialSubject";

    /**
     * Overrides the parts of the Lombok default builder.
     */
    static class CredentialBuilder {
        private List<String> contexts;
        private List<String> types;

        static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        static final String DEFAULT_TYPE = "VerifiableCredential";

        /**
         * Put the default context at the front of the context list provided.
         */
        CredentialBuilder contexts(List<String> contexts) {
            Utils.assertNotNull(contexts, "contexts must not be null");

            this.contexts = new ArrayList<String>(1 + contexts.size());
            this.contexts.add(DEFAULT_CONTEXT);
            this.contexts.addAll(contexts);
            return this;
        }

        /**
         * Put the default type at the front of the type list provided.
         */
        CredentialBuilder types(List<String> types) {
            Utils.assertNotNull(types, "types must not be null");

            this.types = new ArrayList<String>(1 + types.size());
            this.types.add(DEFAULT_TYPE);
            this.types.addAll(types);
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
