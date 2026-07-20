package org.jruby.ext.openssl.util;

import org.jruby.ext.openssl.shim.ErrorShim;

import java.util.function.Function;

public abstract class ExceptionUtil {

    /**
     * Handle potential FIPS operation error
     * @param e
     * @param handler
     */
    public static void handlePotentialOperationError(Throwable e, Function<Throwable, Throwable> handler) {
        if (ErrorShim.isFipsOperationError(e)) {
            Throwable ex = handler.apply(e);
            if (ex != null && ex != e) {
                if (ex.getCause() == null) ex.initCause(e);
                throwException(ex);
            }
        }
        throwException(e);
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwException(Throwable ex) throws E {
        throw (E) ex;
    }
}
