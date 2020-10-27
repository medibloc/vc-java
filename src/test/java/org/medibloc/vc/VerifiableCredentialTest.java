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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VerifiableCredentialTest {
    @Test
    public void issue() throws MalformedURLException, JOSEException, VerifiableCredentialException, JsonProcessingException {
        Map<String, Object> credentialSubject = new HashMap<String, Object>();
        credentialSubject.put("id", "did:panacea:7aR7Cg46JamVbJgk8azVgUm7Prd74ry1Uct87nZqL3ny");

        Map<String, Object> degree = new HashMap<String, Object>();
        degree.put("type", "BachelorDegree");
        degree.put("name", "Bachelor of Science and Arts");
        credentialSubject.put("degree", degree);

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
                .issuanceDate(new Date(System.currentTimeMillis()/1000*1000)) // for equals()
                .credentialSubject(credentialSubject)
                .build();

        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(vc));

        String jwt = vc.sign("ES256K", "my key id", ecJWK.toECPrivateKey());
        System.out.println(jwt);

        VerifiableCredential verified = VerifiableCredential.fromJwt(jwt, ecJWK.toECPublicKey());
        System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(verified));

        assertEquals(vc, verified);
    }
}
