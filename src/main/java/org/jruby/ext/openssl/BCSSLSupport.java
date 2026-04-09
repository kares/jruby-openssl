package org.jruby.ext.openssl;

import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLEngine;

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

    // extract SNI hostname from the negotiated session (server-side)
    static String getRequestedServerName(final SSLEngine engine) {
        SSLSession session = getBCSession(engine);
        if (session instanceof BCExtendedSSLSession) {
            return getServerNameFrom((BCExtendedSSLSession) session);
        }
        if (session instanceof ExtendedSSLSession) {
            return getServerNameFrom((ExtendedSSLSession) session);
        }
        return null;
    }

    private static String getServerNameFrom(final BCExtendedSSLSession session) {
        try {
            List<BCSNIServerName> names = session.getRequestedServerNames();
            if (names != null) {
                for (BCSNIServerName name : names) {
                    if (name instanceof BCSNIHostName) return ((BCSNIHostName) name).getAsciiName();
                }
            }
        } catch (UnsupportedOperationException e) { /* ignore */ }
        return null;
    }

    private static String getServerNameFrom(final ExtendedSSLSession session) {
        try {
            List<SNIServerName> names = session.getRequestedServerNames();
            if (names != null) {
                for (SNIServerName name : names) {
                    if (name instanceof SNIHostName) return ((SNIHostName) name).getAsciiName();
                }
            }
        } catch (UnsupportedOperationException e) { /* ignore */ }
        return null;
    }
}
