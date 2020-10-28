package org.medibloc.vc;

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
@AllArgsConstructor
@Getter
@EqualsAndHashCode
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(alphabetic = true)
public class Issuer {
    private final String id;
    private final Map<String, Object> extras;

    // only for JSON deserialization
    private Issuer() {
        this(null);
    }

    public Issuer(String id) {
        this(id, new HashMap<String, Object>());
    }

    @JsonAnySetter  // to unwrap the Map for JSON ser./deser.
    public void addExtra(String key, Object value) {
        this.extras.put(key, value);
    }

    @JsonAnyGetter  // to unwrap the Map for JSON ser./deser.
    public Map<String, Object> getExtras() {
        return extras;
    }
}
