/*
 * Copyright (c) 2026 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;

/**
 * a key manager chooses which configured certificate and private key to send during TLS
 * EKU (Extended Key Usage) says whether a certificate is meant for a server or client
 * SunJSSE and BCJSSE may skip a configured certificate because of its EKU or the
 * peer's suggested issuers, while MRI would still offer it
 * we let the provider choose normally first, then retry those two cases
 * the provider still checks TLS key and chain rules, and the peer sees the
 * original certificate so it can decide whether to trust it
 *
 * SunJSSE calls the standard methods; BCJSSE calls its own methods to check the full chain
 */
final class SSLKeyManager extends BCX509ExtendedKeyManager {

    private static final String PRIMARY = "primary:";
    private static final String COMPATIBLE = "compatible:";

    private final X509ExtendedKeyManager primary;
    private final X509ExtendedKeyManager compatible;
    private final BCX509ExtendedKeyManager primaryBC;
    private final BCX509ExtendedKeyManager compatibleBC;

    static KeyManager[] create(Provider sslProvider, Map<String, KeyStore.PrivateKeyEntry> entries)
        throws GeneralSecurityException, IOException {
        final X509ExtendedKeyManager primary = nativeManager(sslProvider, entries);
        // try strict selection first, then allow MRI's local EKU behavior if it finds nothing
        final Map<String, KeyStore.PrivateKeyEntry> compatibleEntries = new LinkedHashMap<>();
        boolean hasExtendedKeyUsage = false;
        for (Map.Entry<String, KeyStore.PrivateKeyEntry> item : entries.entrySet()) {
            final KeyStore.PrivateKeyEntry entry = item.getValue();
            final Certificate[] chain = entry.getCertificateChain();
            final X509Certificate leaf = (X509Certificate) chain[0];
            if (leaf.getExtendedKeyUsage() != null) {
                chain[0] = new SelectionCertificate(leaf);
                hasExtendedKeyUsage = true;
            }
            compatibleEntries.put(item.getKey(), new KeyStore.PrivateKeyEntry(entry.getPrivateKey(), chain));
        }
        final X509ExtendedKeyManager compatible = hasExtendedKeyUsage
            ? nativeManager(sslProvider, compatibleEntries) : null;
        return new KeyManager[] { new SSLKeyManager(primary, compatible) };
    }

    private static X509ExtendedKeyManager nativeManager(Provider provider,
        Map<String, KeyStore.PrivateKeyEntry> entries) throws GeneralSecurityException, IOException {
        final KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX", provider);
        factory.init(new SSLKeyStore(entries), null);
        for (KeyManager manager : factory.getKeyManagers()) {
            if (manager instanceof X509ExtendedKeyManager) return (X509ExtendedKeyManager) manager;
        }
        throw new KeyManagementException("provider does not supply an extended X509 key manager");
    }

    private SSLKeyManager(X509ExtendedKeyManager primary, X509ExtendedKeyManager compatible) {
        this.primary = primary;
        this.compatible = compatible;
        this.primaryBC = primary instanceof BCX509ExtendedKeyManager ? (BCX509ExtendedKeyManager) primary : null;
        this.compatibleBC = compatible instanceof BCX509ExtendedKeyManager ? (BCX509ExtendedKeyManager) compatible : null;
    }

    // SunJSSE uses these methods; pass the engine or socket through for native TLS checks
    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return first(selectAliases(issuers, (manager, names) ->
            alias(manager.chooseEngineClientAlias(keyTypes, names, engine))));
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return first(selectAliases(issuers, (manager, names) ->
            alias(manager.chooseEngineServerAlias(keyType, names, engine))));
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return first(selectAliases(issuers, (manager, names) ->
            alias(manager.chooseClientAlias(keyTypes, names, socket))));
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return first(selectAliases(issuers, (manager, names) ->
            alias(manager.chooseServerAlias(keyType, names, socket))));
    }

    // alias lists follow the same fallback order as handshake selection
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return selectAliases(issuers, (manager, names) -> manager.getClientAliases(keyType, names));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return selectAliases(issuers, (manager, names) -> manager.getServerAliases(keyType, names));
    }

    // aliases carry the manager that chose them, so keys resolve through that manager
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (alias == null) return null;
        if (alias.startsWith(PRIMARY)) return primary.getPrivateKey(alias.substring(PRIMARY.length()));
        if (compatible != null && alias.startsWith(COMPATIBLE)) {
            return compatible.getPrivateKey(alias.substring(COMPATIBLE.length()));
        }
        return null;
    }

    // the peer must see the original chain even after compatible selection
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (alias == null) return null;
        if (alias.startsWith(PRIMARY)) {
            return originalChain(primary.getCertificateChain(alias.substring(PRIMARY.length())));
        }
        if (compatible != null && alias.startsWith(COMPATIBLE)) {
            return originalChain(compatible.getCertificateChain(alias.substring(COMPATIBLE.length())));
        }
        return null;
    }

    private interface AliasSelector {
        String[] choose(X509ExtendedKeyManager manager, Principal[] issuers);
    }

    private String[] selectAliases(Principal[] issuers, AliasSelector selector) {
        String[] aliases = selector.choose(primary, issuers);
        if (present(aliases)) return qualify(PRIMARY, aliases);
        if (issuers != null && issuers.length > 0) {
            // MRI offers configured credentials even when issuer hints differ
            aliases = selector.choose(primary, null);
            if (present(aliases)) return qualify(PRIMARY, aliases);
        }
        if (compatible != null) {
            aliases = selector.choose(compatible, null);
            if (present(aliases)) return qualify(COMPATIBLE, aliases);
        }
        return null;
    }

    private static boolean present(String[] aliases) { return aliases != null && aliases.length > 0; }

    private static String[] alias(String alias) { return alias == null ? null : new String[] { alias }; }

    private static String first(String[] aliases) { return present(aliases) ? aliases[0] : null; }

    // native aliases may be versioned; tag which manager owns them
    private static String[] qualify(String prefix, String[] aliases) {
        final String[] result = new String[aliases.length];
        for (int i = 0; i < aliases.length; i++) result[i] = prefix + aliases[i];
        return result;
    }

    private static X509Certificate[] originalChain(X509Certificate[] chain) {
        if (chain == null) return null;
        // send the real certificate; the EKU override is only for local selection
        final X509Certificate[] result = chain.clone();
        for (int i = 0; i < result.length; i++) {
            if (result[i] instanceof SelectionCertificate) {
                result[i] = ((SelectionCertificate) result[i]).original;
            }
        }
        return result;
    }

    private static final class SelectionCertificate extends X509AuxCertificate {
        final X509Certificate original;

        SelectionCertificate(X509Certificate original) {
            super(original);
            this.original = original;
        }

        // hide EKU only while the native manager decides whether to offer this key
        @Override
        public List<String> getExtendedKeyUsage() { return null; }
    }

    // BCJSSE calls these methods directly, so keep its native chain and algorithm checks
    @Override
    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return selectBC(issuers, (manager, names) -> manager.chooseEngineClientKeyBC(keyTypes, names, engine));
    }

    @Override
    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return selectBC(issuers, (manager, names) -> manager.chooseEngineServerKeyBC(keyTypes, names, engine));
    }

    @Override
    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return selectBC(issuers, (manager, names) -> manager.chooseClientKeyBC(keyTypes, names, socket));
    }

    @Override
    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return selectBC(issuers, (manager, names) -> manager.chooseServerKeyBC(keyTypes, names, socket));
    }

    private interface KeySelector {
        BCX509Key choose(BCX509ExtendedKeyManager manager, Principal[] issuers);
    }

    private BCX509Key selectBC(Principal[] issuers, KeySelector selector) {
        if (primaryBC == null) return null;
        BCX509Key key = selector.choose(primaryBC, issuers);
        if (key == null && issuers != null && issuers.length > 0) key = selector.choose(primaryBC, null);
        if (key == null && compatibleBC != null) key = selector.choose(compatibleBC, null);
        if (key == null) return null;
        // keep BC's native checks but return the certificate we were given
        final BCX509Key selected = key;
        return new BCX509Key() {
            @Override
            public String getKeyType() { return selected.getKeyType(); }

            @Override
            public PrivateKey getPrivateKey() { return selected.getPrivateKey(); }

            @Override
            public X509Certificate[] getCertificateChain() { return originalChain(selected.getCertificateChain()); }
        };
    }

    // BC's base class requires this alias lookup hook
    @Override
    protected BCX509Key getKeyBC(String keyType, String alias) {
        final PrivateKey privateKey = getPrivateKey(alias);
        final X509Certificate[] chain = getCertificateChain(alias);
        if (privateKey == null || chain == null || chain.length == 0) return null;
        return new BCX509Key() {
            @Override
            public String getKeyType() { return keyType; }

            @Override
            public PrivateKey getPrivateKey() { return privateKey; }

            @Override
            public X509Certificate[] getCertificateChain() { return chain.clone(); }
        };
    }
}
