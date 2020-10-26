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
import java.util.*;

public class VerifiableCredentialTest {
    @Test
    public void issue() throws MalformedURLException, JOSEException, VerifiableCredentialException, JsonProcessingException {
        Map<String, Object> credentialSubject = new HashMap<String, Object>() {{
            put("id", "did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");
            put("degree", new HashMap<String, Object>() {{
                put("type", "BachelorDegree");
                put("name", "Bachelor of Science and Arts");
            }});
        }};

        // Generate EC key pair on the secp256k1 curve
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("my key ID")
                .generate();

        String issuerDid = "did:panacea:7Prd74ry1Uct87nZqL3ny7aR7Cg46JamVbJgk8azVgUm";
        String issuerVeriMethod = issuerDid + "#key1";

        VerifiableCredential vc = VerifiableCredential.builder()
                .contexts(Collections.singletonList("https://github.com/medibloc/vc-schema/outpatient/v1"))
                .types(Collections.singletonList("OutpatientCredential"))
                .id(new URL("http://k-hospital.com/credentials/100"))
                .issuer(new VerifiableCredential.Issuer(issuerDid, "k-hospital"))
                .issuanceDate(new Date())
                .credentialSubject(credentialSubject)
                .proof(Proof.Type.ES256K, issuerVeriMethod, ecJWK.toECPrivateKey())
                .build();

        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(vc));
    }
}
