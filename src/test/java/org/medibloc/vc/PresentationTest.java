package org.medibloc.vc;

import com.nimbusds.jose.JOSEException;
import org.junit.Test;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class PresentationTest {
    @Test
    public void builder() throws MalformedURLException, ParseException, VerifiableCredentialException, JOSEException {
        Presentation presentation = buildPresentation();

        assertEquals(
                Arrays.asList(Presentation.PresentationBuilder.DEFAULT_CONTEXT, "https://www.w3.org/2018/credentials/examples/v1"),
                presentation.getContexts()
        );
        assertEquals(
                Arrays.asList(Presentation.PresentationBuilder.DEFAULT_TYPE, "CredentialManagerPresentation"),
                presentation.getTypes()
        );
        assertEquals("http://example.edu/presentations/1234", presentation.getId().toString());
        assertEquals("did:panacea:nZqL3ny7aR7Cg46Jct87gk8azVgUmamVbJ7Prd74ry1U", presentation.getHolder());
        assertEquals(1, presentation.getVerifiableCredentials().size());
    }

    @Test(expected = VerifiableCredentialException.class)
    public void buildWithoutDefaultContext() throws VerifiableCredentialException {
        Credential.builder().contexts(Collections.singletonList("https://something.com/v1"));
    }

    @Test(expected = VerifiableCredentialException.class)
    public void buildWithoutDefaultType() throws VerifiableCredentialException {
        Credential.builder().types(Collections.singletonList("https://something.com/v1"));
    }

    @Test
    public void toJson() throws IOException, VerifiableCredentialException, ParseException, JOSEException {
        Presentation presentation = buildPresentation();
        assertEquals(
                "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\"],\"holder\":\"did:panacea:nZqL3ny7aR7Cg46Jct87gk8azVgUmamVbJ7Prd74ry1U\",\"id\":\"http://example.edu/presentations/1234\",\"type\":[\"VerifiablePresentation\",\"CredentialManagerPresentation\"],\"verifiableCredential\":[\"eyJraWQiOiJkaWQ6cGFuYWNlYTo3UHJkNzRyeTFVY3Q4N25acUwzbnk3YVI3Q2c0NkphbVZiSmdrOGF6VmdVbSNrZXkxIiwiYWxnIjoiRVMyNTZLIn0.eyJzdWIiOiJkaWQ6cGFuYWNlYTo3YVI3Q2c0NkphbVZiSmdrOGF6VmdVbTdQcmQ3NHJ5MVVjdDg3blpxTDNueSIsIm5iZiI6MTYwMTg1Nzg1MCwiaXNzIjoiZGlkOnBhbmFjZWE6N1ByZDc0cnkxVWN0ODduWnFMM255N2FSN0NnNDZKYW1WYkpnazhhelZnVW0iLCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczpcL1wvd3d3LnczLm9yZ1wvMjAxOFwvY3JlZGVudGlhbHNcL3YxIiwiaHR0cHM6XC9cL3d3dy53My5vcmdcLzIwMThcL2NyZWRlbnRpYWxzXC9leGFtcGxlc1wvdjEiXX0sImp0aSI6Imh0dHA6XC9cL2V4YW1wbGUuZWR1XC9jcmVkZW50aWFsc1wvMzczMiIsImlzc3VlciI6eyJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In19.9e33oCgJlPqpTwTOe2b45PtaMvlCTwY84imbdvCUFaZ3btV4bUUHXj6qivYgtEMqLjSLLvY3dVLflv8LpD8wvA\"]}",
                presentation.toJson()
        );
    }

    static Presentation buildPresentation() throws MalformedURLException, ParseException, VerifiableCredentialException, JOSEException {
        VerifiableCredential vc = new JwtVerifiableCredential("eyJraWQiOiJkaWQ6cGFuYWNlYTo3UHJkNzRyeTFVY3Q4N25acUwzbnk3YVI3Q2c0NkphbVZiSmdrOGF6VmdVbSNrZXkxIiwiYWxnIjoiRVMyNTZLIn0.eyJzdWIiOiJkaWQ6cGFuYWNlYTo3YVI3Q2c0NkphbVZiSmdrOGF6VmdVbTdQcmQ3NHJ5MVVjdDg3blpxTDNueSIsIm5iZiI6MTYwMTg1Nzg1MCwiaXNzIjoiZGlkOnBhbmFjZWE6N1ByZDc0cnkxVWN0ODduWnFMM255N2FSN0NnNDZKYW1WYkpnazhhelZnVW0iLCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMiLCJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczpcL1wvd3d3LnczLm9yZ1wvMjAxOFwvY3JlZGVudGlhbHNcL3YxIiwiaHR0cHM6XC9cL3d3dy53My5vcmdcLzIwMThcL2NyZWRlbnRpYWxzXC9leGFtcGxlc1wvdjEiXX0sImp0aSI6Imh0dHA6XC9cL2V4YW1wbGUuZWR1XC9jcmVkZW50aWFsc1wvMzczMiIsImlzc3VlciI6eyJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5In19.9e33oCgJlPqpTwTOe2b45PtaMvlCTwY84imbdvCUFaZ3btV4bUUHXj6qivYgtEMqLjSLLvY3dVLflv8LpD8wvA");

        return Presentation.builder()
                .contexts(Arrays.asList(Presentation.PresentationBuilder.DEFAULT_CONTEXT, "https://www.w3.org/2018/credentials/examples/v1"))
                .types(Arrays.asList(Presentation.PresentationBuilder.DEFAULT_TYPE, "CredentialManagerPresentation"))
                .id(new URL("http://example.edu/presentations/1234"))
                .verifiableCredentials(Collections.singletonList(vc))
                .holder("did:panacea:nZqL3ny7aR7Cg46Jct87gk8azVgUmamVbJ7Prd74ry1U")
                .build();
    }
}
