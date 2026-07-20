package org.jruby.ext.openssl.shim;

public final class ErrorShim {
    public static boolean isFipsOperationError(final Throwable ex) {
        assert ex != null;
        return false;
    }
}
