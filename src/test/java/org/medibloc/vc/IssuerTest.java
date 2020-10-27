package org.medibloc.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

public class IssuerTest {
    @Test
    public void jsonWithoutExtra() throws IOException {
        Issuer issuer = new Issuer("id1");

        String json = new ObjectMapper().writeValueAsString(issuer);
        assertEquals("{\"id\":\"id1\"}", json);

        assertEquals(issuer, new ObjectMapper().readValue(json, Issuer.class));
    }

    @Test
    public void jsonWithExtra() throws IOException {
        Issuer issuer = new Issuer("id1");
        issuer.addExtra("name", "my name");

        String json = new ObjectMapper().writeValueAsString(issuer);
        assertEquals("{\"id\":\"id1\",\"name\":\"my name\"}", json);

        assertEquals(issuer, new ObjectMapper().readValue(json, Issuer.class));
    }
}
