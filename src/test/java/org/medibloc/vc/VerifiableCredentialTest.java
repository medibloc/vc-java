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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class VerifiableCredentialTest {
    @Test
    public void issue() throws MalformedURLException, JOSEException, VerifiableCredentialException, JsonProcessingException {
        // Generate EC key pair on the secp256k1 curve
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("my key ID")
                .generate();

        // Prepare the issuer information
        String issuerDid = "did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm";
        String issuerVeriMethod = issuerDid + "#key1";

        Issuer issuer = new Issuer(issuerDid);
        issuer.addExtra("name", "k-hospital");

        // Prepare a credentialSubject
        CredentialSubject credentialSubject = new CredentialSubject("did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
        credentialSubject.addClaim("degree", new HashMap<String, Object>() {{
            put("type", "BachelorDegree");
            put("name", "Bachelor of Science and Arts");
        }});

        // Create a VerifiableCredential
        VerifiableCredential vc = VerifiableCredential.builder()
                .contexts(Collections.singletonList("https://github.com/medibloc/vc-schema/outpatient/v1"))
                .types(Collections.singletonList("OutpatientCredential"))
                .id(new URL("http://k-hospital.com/credentials/100"))
                .issuer(issuer)
                .issuanceDate(new Date(getCurrentTimeSec()))
                .credentialSubject(credentialSubject)
                .build();
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(vc));

        // Sign on VC and Get a serialized JWT
        String jwt = vc.toJwt("ES256K", issuerVeriMethod, ecJWK.toECPrivateKey());
        System.out.println(jwt);

        // Verify the JWT and Get a VerifiableCredential parsed from the JWT payload.
        VerifiableCredential verified = VerifiableCredential.fromJwt(jwt, ecJWK.toECPublicKey());
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(verified));

        // Two VerifiableCredentials must be equal
        assertEquals(vc, verified);
    }

    private static long getCurrentTimeSec() {
        return System.currentTimeMillis() / 1000 * 1000;
    }
}
