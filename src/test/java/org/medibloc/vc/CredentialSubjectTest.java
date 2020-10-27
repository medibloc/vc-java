package org.medibloc.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

public class CredentialSubjectTest {
    @Test
    public void jsonWithoutClaims() throws IOException {
        CredentialSubject cs = new CredentialSubject("id1");

        String json = new ObjectMapper().writeValueAsString(cs);
        assertEquals("{\"id\":\"id1\"}", json);

        assertEquals(cs, new ObjectMapper().readValue(json, CredentialSubject.class));
    }

    @Test
    public void jsonWithClaims() throws IOException {
        CredentialSubject cs = new CredentialSubject("id1");
        cs.addClaim("key1", "value1");

        String json = new ObjectMapper().writeValueAsString(cs);
        assertEquals("{\"id\":\"id1\",\"key1\":\"value1\"}", json);

        assertEquals(cs, new ObjectMapper().readValue(json, CredentialSubject.class));
    }

    @Test
    public void jsonWithoutId() throws IOException {
        CredentialSubject cs = new CredentialSubject();
        cs.addClaim("key1", "value1");

        String json = new ObjectMapper().writeValueAsString(cs);
        assertEquals("{\"key1\":\"value1\"}", json);

        assertEquals(cs, new ObjectMapper().readValue(json, CredentialSubject.class));
    }
}
