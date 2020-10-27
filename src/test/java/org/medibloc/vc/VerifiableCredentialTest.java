package org.medibloc.vc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import static org.junit.Assert.*;

public class VerifiableCredentialTest {
    @Test
    public void builder() throws MalformedURLException {
        VerifiableCredential vc = generateVerifiableCredential();

        assertEquals(
                Arrays.asList(VerifiableCredential.VerifiableCredentialBuilder.DEFAULT_CONTEXT, "https://github.com/medibloc/vc-schema/outpatient/v1"),
                vc.getContexts()
        );
        assertEquals(
                Arrays.asList(VerifiableCredential.VerifiableCredentialBuilder.DEFAULT_TYPE, "OutpatientCredential"),
                vc.getTypes()
        );
        assertEquals("http://k-hospital.com/credentials/100", vc.getId().toString());
        assertNotNull(vc.getIssuer());
        assertNotNull(vc.getCredentialSubject());
        assertNotNull(vc.getIssuanceDate());
        assertNull(vc.getExpirationDate());
    }

    @Test
    public void signAndVerify() throws MalformedURLException, JOSEException, VerifiableCredentialException, JsonProcessingException {
        VerifiableCredential vc = generateVerifiableCredential();
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(vc));

        // Generate EC key pair on the secp256k1 curve
        ECKey key = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(vc.getIssuer().getId() + "#key1") // in the format of the DID verification method
                .generate();

        // Sign on VC and Get a serialized JWT
        String jwt = vc.toJwt("ES256K", key.getKeyID(), key.toECPrivateKey());
        System.out.println(jwt);

        // Verify the JWT and Get a VerifiableCredential parsed from the JWT payload.
        VerifiableCredential verified = VerifiableCredential.fromJwt(jwt, key.toECPublicKey());
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(verified));

        // Two VerifiableCredentials must be equal
        assertEquals(vc, verified);
    }

    @Test(expected = VerifiableCredentialException.class)
    public void toJwtWithInvalidAlgo() throws MalformedURLException, JOSEException, VerifiableCredentialException {
        VerifiableCredential vc = generateVerifiableCredential();
        ECKey key = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(vc.getIssuer().getId() + "#key1") // in the format of the DID verification method
                .generate();

        vc.toJwt("INVALID", key.getKeyID(), key.toECPrivateKey());
    }

    private static VerifiableCredential generateVerifiableCredential() throws MalformedURLException {
        // Prepare the issuer information
        Issuer issuer = new Issuer("did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm");
        issuer.addExtra("name", "k-hospital");

        // Prepare a credentialSubject
        CredentialSubject credentialSubject = new CredentialSubject("did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
        credentialSubject.addClaim("degree", new HashMap<String, Object>() {{
            put("type", "BachelorDegree");
            put("name", "Bachelor of Science and Arts");
        }});

        // Create a VerifiableCredential
        return VerifiableCredential.builder()
                .contexts(Collections.singletonList("https://github.com/medibloc/vc-schema/outpatient/v1"))
                .types(Collections.singletonList("OutpatientCredential"))
                .id(new URL("http://k-hospital.com/credentials/100"))
                .issuer(issuer)
                .issuanceDate(new Date(getCurrentTimeSec()))
                .credentialSubject(credentialSubject)
                .build();
    }

    private static long getCurrentTimeSec() {
        return System.currentTimeMillis() / 1000 * 1000;
    }

}
