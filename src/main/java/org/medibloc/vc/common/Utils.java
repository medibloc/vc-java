package org.medibloc.vc.common;

import java.util.List;

public class Utils {
    public static void assertNotNull(Object obj, String msg) throws IllegalArgumentException {
        if (obj == null) {
            throw new IllegalArgumentException(msg);
        }
    }

    public static <T> Object simplifyList(List<T> list) {
        if (list == null) {
            return null;
        }
        return list.size() == 1 ? list.get(0) : list;
    }
}
