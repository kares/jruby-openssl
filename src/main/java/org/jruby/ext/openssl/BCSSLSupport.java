package org.jruby.ext.openssl;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLEngine;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

abstract class BCSSLSupport {

    static SSLSession getBCSession(final SSLEngine engine) {
        // BCSSLEngine.getBCSession() returns the unwrapped BCExtendedSSLSession;
        // engine.getSession() would wrap it in a package-private ExportSSLSession
        if (engine instanceof BCSSLEngine) return ((BCSSLEngine) engine).getBCSession();
        return engine.getSession();
    }

    static boolean setBCSessionToResume(final SSLEngine engine, final SSLSession session) {
        if (engine instanceof BCSSLEngine && session instanceof BCExtendedSSLSession) {
            ((BCSSLEngine) engine).setBCSessionToResume((BCExtendedSSLSession) session);
            return true;
        }
        return false;
    }
}
