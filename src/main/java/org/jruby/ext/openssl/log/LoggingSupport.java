/*
 * The MIT License
 *
 * Copyright 2026 Karol Bucek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl.log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;
import org.jruby.util.SafePropertyAccessor;

/**
 * @author kares
 */
public abstract class LoggingSupport {

    static volatile Function<String, org.jruby.ext.openssl.log.Logger>
            loggerFactory = defaultLoggerFactory();

    static Function<String, org.jruby.ext.openssl.log.Logger> defaultLoggerFactory() {
        return (name) -> new DefaultLogger(name);
    }

    private static class JULLoggerFactory implements Function<String, org.jruby.ext.openssl.log.Logger> {
        @Override
        public org.jruby.ext.openssl.log.Logger apply(final String name) {
            return new JULLogger(name);
        }
    }

    public static void boostrapLoggerFactory() {
        final String loggerType = SafePropertyAccessor.getProperty("jruby.openssl.log.logger");
        if ("jul".equalsIgnoreCase(loggerType)) {
            loggerFactory = new JULLoggerFactory();
        } else {
            loggerFactory = defaultLoggerFactory();
        }
    }

    private static final Map<String, String> BC_LOGGER_SILENCE_LEVELS;
    static {
        Map<String, String> map = new LinkedHashMap<>(4, 1.0F);
        // init-time property/constraints reports: benign informational chatter
        map.put("org.bouncycastle.jsse.provider.PropertyUtils", Level.SEVERE.getName());
        map.put("org.bouncycastle.jsse.provider.DisabledAlgorithmConstraints", Level.SEVERE.getName());
        // per-handshake INFO; leave WARNING visible so real protocol issues show
        map.put("org.bouncycastle.jsse.provider.ProvTlsServer", Level.WARNING.getName());
        map.put("org.bouncycastle.jsse.provider.ProvTlsClient", Level.WARNING.getName());
        BC_LOGGER_SILENCE_LEVELS = map;
    }

    static boolean usingJulLogger() {
        return loggerFactory instanceof JULLoggerFactory;
    }

    private static volatile java.util.logging.Logger[] silencedLoggers;

    /**
     * Applies sensible default {@code java.util.logging} (JUL) levels to a handful
     * of known-noisy BouncyCastle / BCJSSE loggers — but only when the user has
     * not configured JUL themselves and has not explicitly opted out.
     *
     * <p>
     * BCJSSE emits some INFO/WARNING lines at first-load and per-handshake :
     * <ul>
     *   <li>{@code org.bouncycastle.jsse.provider.PropertyUtils} init-time report
     *       of JDK-wide disabled-algorithm policies picked up by BC-JSSE</li>
     *   <li>{@code org.bouncycastle.jsse.provider.DisabledAlgorithmConstraints}
     *       Oracle-specific warning that BC-JSSE doesn't support</li>
     *   <li>{@code org.bouncycastle.jsse.provider.ProvTlsServer/ProvTlsClient}
     *       per-handshake connection-start/complete INFO lines</li>
     * </ul>
     *
     * @author kares
     */
    public static synchronized void silenceBouncyCastleLoggers() {
        if (silencedLoggers != null) return;

        String logSilence = SafePropertyAccessor.getProperty("jruby.openssl.log.silence");
        // NOTE: bootstrapLoggerFactory is expected to happen before silenceBouncyCastleLoggers
        if (logSilence != null && !Boolean.parseBoolean(logSilence)) return; // silence by default
        if (logSilence == null && usingJulLogger()) return; // do not silence when using JUL

        if (userConfiguredJULOrBCLogging()) {
            silencedLoggers = new java.util.logging.Logger[0];
            return;
        }

        try {
            if (updateConfigurationForSilencedLoggers()) {
                silencedLoggers = new java.util.logging.Logger[0];
                return;
            }

            silencedLoggers = setSilencedLoggerLevels();
        }
        catch (SecurityException ex) {
            OpenSSL.debug("unable to configure BC logging levels", ex);
            silencedLoggers = new java.util.logging.Logger[0];
        }
    }

    /**
     * Java 9+ path: merge silenced logger levels into the {@link LogManager}'s
     * configuration properties via {@code updateConfiguration(InputStream, Function)}.
     *
     * The configuration is consulted by every subsequent
     * {@link Logger#getLogger(String)} regardless of the caller's module.
     *
     * @return {@code true} when applied (on Java 9+)
     */
    private static boolean updateConfigurationForSilencedLoggers() {
        final Method updateConfiguration;
        try {
            updateConfiguration = LogManager.class.getMethod(
                    "updateConfiguration", InputStream.class, Function.class);
        }
        catch (NoSuchMethodException ignore) {
            return false; // on Java 8
        }

        try {
            final Properties props = new Properties();
            for (Map.Entry<String, String> e : BC_LOGGER_SILENCE_LEVELS.entrySet()) {
                props.setProperty(e.getKey() + ".level", e.getValue());
            }
            final ByteArrayOutputStream stream = new ByteArrayOutputStream();
            props.store(stream, null);

            // for keys in our stream, adopt the new value; leave everything else untouched
            final Function<String, BiFunction<String, String, String>> mapper = key -> {
                if (key != null && key.endsWith(".level")) {
                    final String name = key.substring(0, key.length() - ".level".length());
                    if (BC_LOGGER_SILENCE_LEVELS.containsKey(name)) {
                        return (oldValue, newValue) -> newValue;
                    }
                }
                return null; // no change for other keys
            };

            updateConfiguration.invoke(LogManager.getLogManager(),
                    new ByteArrayInputStream(stream.toByteArray()),
                    mapper);

            return true;
        }
        catch (ReflectiveOperationException | IOException ex) {
            OpenSSL.debug("LogManager.updateConfiguration failed", ex);
            return false;
        }
    }

    /**
     * Java 8 fallback: create/retrieve each logger and set its level directly,
     * retaining strong references so JUL's weak-logger policy.
     */
    private static Logger[] setSilencedLoggerLevels() {
        final Logger[] loggers = new Logger[BC_LOGGER_SILENCE_LEVELS.size()];
        int i = 0;
        for (Map.Entry<String, String> e : BC_LOGGER_SILENCE_LEVELS.entrySet()) {
            final Logger logger = Logger.getLogger(e.getKey());
            logger.setLevel(Level.parse(e.getValue()));
            loggers[i++] = logger;
        }
        return loggers;
    }

    /**
     * @return {@code true} if the user has configured JUL for the
     *         {@code org.bouncycastle} hierarchy in any detectable way
     */
    private static boolean userConfiguredJULOrBCLogging() {
        // if there's explicit JUL configuration than don't do any adjustments
        if (SafePropertyAccessor.getProperty("java.util.logging.config.file")  != null) return true;
        if (SafePropertyAccessor.getProperty("java.util.logging.config.class") != null) return true;

        final LogManager logManager = LogManager.getLogManager();

        final List<String> loggerNames =  new ArrayList<>(8);
        loggerNames.add("org.bouncycastle");
        loggerNames.add("org.bouncycastle.jsse");
        loggerNames.add("org.bouncycastle.jsse.provider");
        loggerNames.addAll(BC_LOGGER_SILENCE_LEVELS.keySet());

        for (String name : loggerNames) {
            // programmatic setLevel prior to us
            if (Logger.getLogger(name).getLevel() != null) return true;
            // any non-null value implies user config
            if (logManager.getProperty(name + ".level") != null) return true;
        }
        return false;
    }
}
