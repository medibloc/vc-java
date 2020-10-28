package org.medibloc.vc;

import com.nimbusds.jose.shaded.json.JSONArray;

import java.util.*;

class JwtObjectDecoder {
    /**
     * Create a list from an object parsed by Nimbus JOSE JWT library, if possible.
     * This methods expects the object is T or {@link JSONArray} which extends {@link ArrayList}.
     */
    static <T> List<T> toList(Object obj, Class<T> valueType) throws VerifiableCredentialException {
        if (obj == null) {
            return null;
        }

        if (valueType.isInstance(obj)) {
            return Collections.singletonList(valueType.cast(obj));
        } else if (obj instanceof JSONArray) {
            JSONArray arr = (JSONArray) obj;
            List<T> ret = new ArrayList<T>(arr.size());
            for (Object o : arr) {
                if (valueType.isInstance(o)) {
                    ret.add(valueType.cast(o));
                } else {
                    throw new VerifiableCredentialException("list contains unexpected object: " + o);
                }
            }
            return ret;
        }

        throw new VerifiableCredentialException("unexpected object: " + obj);
    }

    /**
     * Create a <code>Map<T, Object></code> from an object parsed by Nimbus JOSE JWT library, if possible.
     * This method expects the object is a {@link com.nimbusds.jose.shaded.json.JSONObject} which extends {@link HashMap}.
     */
    static <T> Map<T, Object> toMap(Object obj, Class<T> keyType) throws VerifiableCredentialException {
        if (obj == null) {
            return null;
        }

        if (obj instanceof Map) {
            Map<T, Object> map = new HashMap<T, Object>();
            for (Map.Entry<?,?> entry : ((Map<?, ?>) obj).entrySet()) {
                if (keyType.isInstance(entry.getKey())) {
                    map.put(keyType.cast(entry.getKey()), entry.getValue());
                } else {
                    throw new VerifiableCredentialException("key is not " + keyType);
                }
            }
            return map;
        }

        throw new VerifiableCredentialException("object is not a map");
    }
}
