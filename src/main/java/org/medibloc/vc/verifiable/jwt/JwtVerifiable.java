package org.medibloc.vc.verifiable.jwt;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import org.medibloc.vc.VerifiableCredentialException;
import org.medibloc.vc.lang.Assert;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

@AllArgsConstructor
@Getter
@EqualsAndHashCode
class JwtVerifiable {
    @JsonValue
    @NonNull
    private final String jws;

    JwtVerifiable(String algo, String keyId, PrivateKey privateKey, JwtBuilder jwtBuilder) throws VerifiableCredentialException {
        Assert.notNull(algo, "keyType must not be null");
        Assert.notNull(keyId, "keyId must not be null");
        Assert.notNull(privateKey, "privateKey must not be null");
        Assert.notNull(jwtBuilder, "jwtBuilder must not be null");

        try {
            this.jws = jwtBuilder
                    .setHeaderParam("kid", keyId)
                    .signWith(privateKey, SignatureAlgorithm.forName(algo))
                    .serializeToJsonWith(new JacksonSerializer(new ObjectMapper()))
                    .compact();
        } catch (Exception e) {
            throw new VerifiableCredentialException(e);
        }
    }

    Jws<Claims> verifyJwt(PublicKey publicKey, Map<String, Class> classMap) throws VerifiableCredentialException {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .deserializeJsonWith(new JacksonDeserializer(classMap))
                    .build()
                    .parseClaimsJws(this.jws);
        } catch (Exception e) {
            throw new VerifiableCredentialException(e);
        }
    }

    public String serialize() {
        return this.jws;
    }
}
