package org.medibloc.vc.lang;

public class Assert {
    public static void notNull(Object obj, String msg) throws IllegalArgumentException {
        if (obj == null) {
            throw new IllegalArgumentException(msg);
        }
    }
}
