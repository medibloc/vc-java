package org.medibloc.vc;

class Utils {
    static void assertNotNull(Object obj, String msg) throws IllegalArgumentException {
        if (obj == null) {
            throw new IllegalArgumentException(msg);
        }
    }
}
