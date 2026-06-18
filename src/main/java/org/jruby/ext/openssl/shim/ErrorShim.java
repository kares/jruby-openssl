package org.jruby.ext.openssl.shim;

public abstract class ErrorShim {
    public static boolean isFipsOperationError(final Throwable ex) {
        assert ex != null;
        return false;
    }
}
