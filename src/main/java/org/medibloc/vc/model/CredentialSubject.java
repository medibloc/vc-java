package org.medibloc.vc.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a credentialSubject defined at https://www.w3.org/TR/vc-data-model/#credential-subject.
 */
@AllArgsConstructor
@Getter
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

    // to unflatten key-values into a Map for JSON deserialization
    // {"id":"id1","key1":"val1"} -> CredentialSubject{id:"id1", claims:{"key1":"value1"}}
    @JsonAnySetter
    public void addClaim(String key, Object value) {
        this.claims.put(key, value);
    }

    // to flatten a Map for JSON serialization
    // CredentialSubject{id:"id1", claims:{"key1":"value1"}} -> {"id":"id1","key1":"val1"}
    @JsonAnyGetter
    public Map<String, Object> getClaims() {
        return claims;
    }
}
