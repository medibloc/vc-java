package org.medibloc.vc;

import java.util.List;

class Utils {
    static void assertNotNull(Object obj, String msg) throws IllegalArgumentException {
        if (obj == null) {
            throw new IllegalArgumentException(msg);
        }
    }

    static <T> Object simplifyList(List<T> list) {
        if (list == null) {
            return null;
        }
        return list.size() == 1 ? list.get(0) : list;
    }
}
