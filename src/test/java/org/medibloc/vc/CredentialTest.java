package org.medibloc.vc;

import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import static org.junit.Assert.*;

public class CredentialTest {
    @Test
    public void builder() throws MalformedURLException {
        Credential vc = buildCredential();

        assertEquals(
                Arrays.asList(Credential.CredentialBuilder.DEFAULT_CONTEXT, "https://github.com/medibloc/vc-schema/outpatient/v1"),
                vc.getContexts()
        );
        assertEquals(
                Arrays.asList(Credential.CredentialBuilder.DEFAULT_TYPE, "OutpatientCredential"),
                vc.getTypes()
        );
        assertEquals("http://k-hospital.com/credentials/100", vc.getId().toString());
        assertNotNull(vc.getIssuer());
        assertNotNull(vc.getCredentialSubject());
        assertNotNull(vc.getIssuanceDate());
        assertNull(vc.getExpirationDate());
    }

    static Credential buildCredential() throws MalformedURLException {
        // Prepare the issuer information
        Issuer issuer = new Issuer("did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm");
        issuer.addExtra("name", "Example University");

        // Prepare a credentialSubject
        CredentialSubject credentialSubject = new CredentialSubject("did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
        credentialSubject.addClaim("degree", new HashMap<String, Object>() {{
            put("type", "BachelorDegree");
            put("name", "Bachelor of Science and Arts");
        }});

        // Create a VerifiableCredential
        return Credential.builder()
                .contexts(Collections.singletonList("https://www.w3.org/2018/credentials/examples/v1"))
                .types(Collections.singletonList("UniversityDegreeCredential"))
                .id(new URL("http://example.edu/credentials/3732"))
                .issuer(issuer)
                .issuanceDate(new Date(getCurrentTimeSec()))
                .credentialSubject(credentialSubject)
                .build();
    }

    private static long getCurrentTimeSec() {
        return System.currentTimeMillis() / 1000 * 1000;
    }

}
