package org.medibloc.vc.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.common.Utils;
import org.medibloc.vc.verifiable.VerifiableCredential;

import java.net.URL;
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
@AllArgsConstructor(access = AccessLevel.PUBLIC)
@Getter
@EqualsAndHashCode(callSuper = true)
@ToString
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Credential extends JsonSerializable {
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
    public static final String JSON_PROP_CONTEXTS = "@context";
    public static final String JSON_PROP_TYPES = "type";
    public static final String JSON_PROP_CRED_SUB = "credentialSubject";

    /**
     * Overrides the parts of the Lombok default builder.
     */
    static class CredentialBuilder {
        private List<String> contexts;
        private List<String> types;

        static final String DEFAULT_CONTEXT = "https://www.w3.org/2018/credentials/v1";
        static final String DEFAULT_TYPE = "VerifiableCredential";

        /**
         * Validate the contexts
         */
        CredentialBuilder contexts(List<String> contexts) throws VerifiableCredentialException {
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
        CredentialBuilder types(List<String> types) throws VerifiableCredentialException {
            Utils.assertNotNull(types, "types must not be null");
            if (!types.contains(DEFAULT_TYPE)) {
                throw new VerifiableCredentialException("types must contain the default type: " + DEFAULT_TYPE);
            }
            this.types = types;
            return this;
        }
    }
}
