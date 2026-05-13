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
 * Applies sensible default {@code java.util.logging} (JUL) levels to a handful
 * of known-noisy BouncyCastle / BCJSSE loggers — but only when the user has
 * not configured JUL themselves and has not explicitly opted out.
 *
 * <h2>What gets silenced</h2>
 * BCJSSE emits some INFO/WARNING lines at first-load and per-handshake :
 * <ul>
 *   <li>{@code org.bouncycastle.jsse.provider.PropertyUtils} init-time report
 *       of JDK-wide disabled-algorithm policies picked up by BCJSSE</li>
 *   <li>{@code org.bouncycastle.jsse.provider.DisabledAlgorithmConstraints}
 *       warnings about Oracle-specific extended syntax in
 *       {@code jdk.certpath.disabledAlgorithms} that BCJSSE's parser doesn't
 *       support (falls back cleanly)</li>
 *   <li>{@code org.bouncycastle.jsse.provider.ProvTlsServer/ProvTlsClient}
 *       per-handshake connection-start/complete INFO lines</li>
 * </ul>
 *
 * @author kares
 */
public class LoggingSupport {

    private LoggingSupport() { /* no instances */ }

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

    private static volatile java.util.logging.Logger[] silencedLoggers;

    /**
     * Apply default silencing for noisy BC loggers
     */
    public static synchronized void silenceBouncyCastleLoggers() {
        if (silencedLoggers != null) return;

        if (!SafePropertyAccessor.getBoolean("jruby.openssl.jul.silence", true)) return;

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
     * The configuration is consulted by every subsequent
     * {@link Logger#getLogger(String)} regardless of the caller's module,
     * which side-steps any concern about caller-context with caller sesitive resolution.
     *
     * @return {@code true} when applied (Java 9+)
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
