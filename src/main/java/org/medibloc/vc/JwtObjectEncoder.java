package org.medibloc.vc;

import java.util.ArrayList;
import java.util.List;

class JwtObjectEncoder {
    static Object fromVerifiableCredential(VerifiableCredential vc) throws VerifiableCredentialException {
        if (vc instanceof JwtVerifiableCredential) {
            return ((JwtVerifiableCredential) vc).getJwt();
        }
        throw new VerifiableCredentialException("unsupported VerifiableCredential type: " + vc.getClass());
    }

    static List<Object> fromVerifiableCredentials(List<VerifiableCredential> vcList) throws VerifiableCredentialException {
        List<Object> ret = new ArrayList<Object>(vcList.size());
        for (VerifiableCredential vc : vcList) {
            ret.add(JwtObjectEncoder.fromVerifiableCredential(vc));
        }
        return ret;
    }

}
