package org.medibloc.vc;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a credentialSubject defined at https://www.w3.org/TR/vc-data-model/#credential-subject.
 */
@AllArgsConstructor
@Getter
@ToString
@EqualsAndHashCode
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class CredentialSubject {
    private final String id;
    private final Map<String, Object> claims;

    public CredentialSubject() {
        this(null, new HashMap<String, Object>());  // id is optional
    }

    public CredentialSubject(String id) {
        this(id, new HashMap<String, Object>());
    }

    @JsonAnySetter  // to unwrap the Map for JSON ser./deser.
    public void addClaim(String key, Object value) {
        this.claims.put(key, value);
    }

    @JsonAnyGetter  // to unwrap the Map for JSON ser./deser.
    public Map<String, Object> getClaims() {
        return claims;
    }
}
