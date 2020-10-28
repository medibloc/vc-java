package org.medibloc.vc;

import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.TimeZone;

import static org.junit.Assert.*;

public class CredentialTest {
    @Test
    public void builder() throws MalformedURLException, ParseException {
        Credential vc = buildCredential();

        assertEquals(
                Arrays.asList(Credential.CredentialBuilder.DEFAULT_CONTEXT, "https://www.w3.org/2018/credentials/examples/v1"),
                vc.getContexts()
        );
        assertEquals(
                Arrays.asList(Credential.CredentialBuilder.DEFAULT_TYPE, "UniversityDegreeCredential"),
                vc.getTypes()
        );
        assertEquals("http://example.edu/credentials/3732", vc.getId().toString());
        assertNotNull(vc.getIssuer());
        assertNotNull(vc.getCredentialSubject());
        assertNotNull(vc.getIssuanceDate());
        assertNull(vc.getExpirationDate());
    }

    @Test
    public void toJson() throws MalformedURLException, VerifiableCredentialException, ParseException {
        Credential vc = buildCredential();
        assertEquals(
                "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\"],\"credentialSubject\":{\"id\":\"did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny\",\"degree\":{\"name\":\"Bachelor of Science and Arts\",\"type\":\"BachelorDegree\"}},\"id\":\"http://example.edu/credentials/3732\",\"issuanceDate\":\"2020-10-05T12:30:50Z\",\"issuer\":{\"id\":\"did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm\",\"name\":\"Example University\"},\"type\":[\"VerifiableCredential\",\"UniversityDegreeCredential\"]}",
                vc.toJson()
        );
    }

    static Credential buildCredential() throws MalformedURLException, ParseException {
        // Prepare the issuer information
        Issuer issuer = new Issuer("did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm");
        issuer.addExtra("name", "Example University");

        // Prepare a credentialSubject
        CredentialSubject credentialSubject = new CredentialSubject("did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
        credentialSubject.addClaim("degree", new HashMap<String, Object>() {{
            put("type", "BachelorDegree");
            put("name", "Bachelor of Science and Arts");
        }});

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

        // Create a VerifiableCredential
        return Credential.builder()
                .contexts(Collections.singletonList("https://www.w3.org/2018/credentials/examples/v1"))
                .types(Collections.singletonList("UniversityDegreeCredential"))
                .id(new URL("http://example.edu/credentials/3732"))
                .issuer(issuer)
                .issuanceDate(dateFormat.parse("2020-10-05 12:30:50"))
                .credentialSubject(credentialSubject)
                .build();
    }
}
