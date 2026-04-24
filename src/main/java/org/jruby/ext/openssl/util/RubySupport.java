package org.jruby.ext.openssl.util;

import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

public abstract class RubySupport {

    public static CharSequence callerTraceAt(final ThreadContext context, final int level) {
        final IRubyObject caller0 = context.runtime.getKernel().callMethod(
                "caller",
                context.runtime.newFixnum(level),
                context.runtime.newFixnum(1)
        );

        if (caller0.isNil()) return null;
        final IRubyObject first = caller0.convertToArray().eltInternal(0);
        return first instanceof RubyString ? (RubyString) first : first.asString();
    }
}
