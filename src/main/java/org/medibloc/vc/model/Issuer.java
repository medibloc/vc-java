package org.medibloc.vc.model;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a issuer defined at https://www.w3.org/TR/vc-data-model/#issuer.
 */
@Getter
@EqualsAndHashCode
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Issuer {
    @NonNull
    private final String id;
    @NonNull
    private final Map<String, Object> extras;

    // only for JSON deserialization
    private Issuer() {
        this(null);
    }

    public Issuer(String id) {
        this(id, null);
    }

    public Issuer(String id, Map<String, Object> extras) {
        this.id = id;
        this.extras = extras != null ? extras : new HashMap<String, Object>();
    }

    // to unflatten key-values into a Map for JSON deserialization
    // {"id":"id1","key1":"val1"} -> Issuer{id:"id1", extras:{"key1":"value1"}}
    @JsonAnySetter
    public void addExtra(String key, Object value) {
        this.extras.put(key, value);
    }

    // to flatten a Map for JSON serialization
    // Issuer{id:"id1", extras:{"key1":"value1"}} -> {"id":"id1","key1":"val1"}
    @JsonAnyGetter
    public Map<String, Object> getExtras() {
        return extras;
    }
}
