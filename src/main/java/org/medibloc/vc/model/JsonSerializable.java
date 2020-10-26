package org.medibloc.vc.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.EqualsAndHashCode;
import org.medibloc.vc.VerifiableCredentialException;

@EqualsAndHashCode
class JsonSerializable {
    public String toJson() throws VerifiableCredentialException {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new VerifiableCredentialException(e);
        }
    }
}
