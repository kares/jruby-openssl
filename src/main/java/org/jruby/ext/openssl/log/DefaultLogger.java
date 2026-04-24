package org.jruby.ext.openssl.log;

import org.jruby.Ruby;
import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.runtime.ThreadContext;

final class DefaultLogger implements Logger {

    private final String name;

    DefaultLogger(final String name) {
        this.name = name;
    }

    @Override
    public boolean isDebug(final Ruby runtime) {
        return OpenSSL.isDebug();
    }

    private boolean isWarn() {
        return OpenSSL.isWarn();
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg) {
        if (!isDebug(runtime)) return;

        System.out.println(msgWithPrefix(msg, false));
    }

    @Override
    public void debug(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        System.out.println(msgWithPrefix(msg, true) + ex);
    }

    @Override
    public void debugStack(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isDebug(runtime)) return;

        synchronized (System.out) {
            System.out.print(msgWithPrefix(msg, true));
            ex.printStackTrace(System.out);
        }
    }

    @Override
    public void info(Ruby runtime, CharSequence msg) {
        debug(runtime, msg);
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg) {
        if (!isWarn()) return;

        final String message = msgWithPrefix(msg, false);
        if (runtime != null) {
            OpenSSL.warn(runtime.getCurrentContext(), message);
        }
        else {
            System.err.println(message);
        }
    }

    @Override
    public void warn(final Ruby runtime, final CharSequence msg, final Throwable ex) {
        if (!isWarn()) return;

        final String message = msgWithPrefix(msg, true) + ex;
        if (runtime != null) {
            OpenSSL.warn(runtime.getCurrentContext(), message);
        }
        else {
            System.err.println(message);
        }
    }


    @Override
    public void warnWithCaller(final Ruby runtime, CharSequence msg) {
        if (!isWarn()) return;

        if (runtime != null) {
            final ThreadContext context = runtime.getCurrentContext();
            final CharSequence caller = RubySupport.callerTraceAt(context, 1);
            if (caller != null) msg = msgWithPrefix(msg, true) + '<' + caller + '>';
            else msg = msgWithPrefix(msg, false);
            OpenSSL.warn(context, msg);
        }
        else {
            System.err.println(msgWithPrefix(msg, false));
        }
    }

    private String msgWithPrefix(final CharSequence msg, final boolean space) {
        return '[' + name + "] " + (msg == null ? "" : msg) + (space ? ' ' : "");
    }
}
