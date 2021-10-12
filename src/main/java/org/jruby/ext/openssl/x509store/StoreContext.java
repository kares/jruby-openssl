/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.x509store;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.jruby.ext.openssl.SecurityHelper;

import static org.jruby.ext.openssl.x509store.X509Error.addError;
import static org.jruby.ext.openssl.x509store.X509Utils.*;

/**
 * c: X509_STORE_CTX
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class StoreContext {

    private static final Integer ZERO = 0;

    private final Store store;

    private int currentMethod;

    X509AuxCertificate certificate;
    List<X509AuxCertificate> untrusted;
    List<X509CRL> crls;

    public VerifyParameter verifyParameter;

    public List<X509AuxCertificate> otherContext;

    public StoreContext(final Store store) {
        this.store = store;
    }

    public static interface CheckPolicyFunction extends Function1<StoreContext> {
        public static final CheckPolicyFunction EMPTY = new CheckPolicyFunction(){
            public int call(StoreContext context) {
                return -1;
            }
        };
    }

    Store.VerifyFunction verify;
    Store.VerifyCallbackFunction verifyCallback;
    Store.GetIssuerFunction getIssuer;
    Store.CheckIssuedFunction checkIssued;
    Store.CheckRevocationFunction checkRevocation;
    Store.GetCRLFunction getCRL;
    Store.CheckCRLFunction checkCRL;
    Store.CertificateCRLFunction certificateCRL;
    CheckPolicyFunction checkPolicy;
    Store.CleanupFunction cleanup;

    public boolean isValid;

    private int lastUntrusted;
    private ArrayList<X509AuxCertificate> chain;

    public PolicyTree tree;

    public int explicitPolicy;

    public int error;
    public int errorDepth;

    X509AuxCertificate currentCertificate;
    X509AuxCertificate currentIssuer;
    X509CRL currentCRL;
    //int current_crl_score;
    //int current_reasons;

    List<Object> extraData;

    public Store getStore() {
        return store;
    }

    /**
     * c: X509_STORE_CTX_set_depth
     */
    public void setDepth(int depth) {
        verifyParameter.setDepth(depth);
    }

    /**
     * c: X509_STORE_CTX_set_app_data
     */
    public void setApplicationData(Object data) {
        setExtraData(0, data);
    }

    /**
     * c: X509_STORE_CTX_get_app_data
     */
    public Object getApplicationData() {
        return getExtraData(0);
    }

    /**
     * c: X509_STORE_CTX_get1_issuer
     */
    int getFirstIssuer(final X509AuxCertificate[] issuers, final X509AuxCertificate x) throws Exception {
        final Name xn = new Name( x.getIssuerX500Principal() );
        final X509Object[] s_obj = new X509Object[1];
        int ok = store == null ? 0 : getBySubject(X509Utils.X509_LU_X509, xn, s_obj);
        if ( ok != X509Utils.X509_LU_X509 ) {
            if ( ok == X509Utils.X509_LU_RETRY ) {
                X509Error.addError(X509Utils.X509_R_SHOULD_RETRY);
                return -1;
            }
            else if ( ok != X509Utils.X509_LU_FAIL ) {
                return -1;
            }
            return 0;
        }

        X509Object obj = s_obj[0];
        if ( checkIssued.call(this, x, ((Certificate) obj).cert) != 0 ) {
            issuers[0] = ((Certificate) obj).cert;
            return 1;
        }

        List<X509Object> objects = store.getObjects();
        int idx = X509Object.indexBySubject(objects, X509Utils.X509_LU_X509, xn);
        if ( idx == -1 ) return 0;

        /* Look through all matching certificates for a suitable issuer */
        for ( int i = idx; i < objects.size(); i++ ) {
            final X509Object pobj = objects.get(i);
            if ( pobj.type() != X509Utils.X509_LU_X509 ) {
                return 0;
            }
            final X509AuxCertificate x509 = ((Certificate) pobj).cert;
            if ( ! xn.equalTo( x509.getSubjectX500Principal() ) ) {
                return 0;
            }
            if ( checkIssued.call(this, x, x509) != 0 ) {
                issuers[0] = x509;
                return 1;
            }
        }
        return 0;
    }

    public static List<X509AuxCertificate> ensureAux(final Collection<X509Certificate> input) {
        if ( input == null ) return null;

        List<X509AuxCertificate> out = new ArrayList<X509AuxCertificate>(input.size());
        for ( X509Certificate cert : input ) out.add( ensureAux(cert) );
        return out;
    }

    public static List<X509AuxCertificate> ensureAux(final X509Certificate[] input) {
        if ( input == null ) return null;

        List<X509AuxCertificate> out = new ArrayList<X509AuxCertificate>(input.length);
        for ( X509Certificate cert : input ) out.add( ensureAux(cert) );
        return out;
    }

    public static X509AuxCertificate ensureAux(final X509Certificate input) {
        if ( input == null ) return null;

        if ( input instanceof X509AuxCertificate ) {
            return (X509AuxCertificate) input;
        }
        return new X509AuxCertificate(input);
    }

    /**
     * c: X509_STORE_CTX_init
     */
    public int init(X509AuxCertificate cert, List<X509AuxCertificate> chain) {
        int ret = 1;
        this.currentMethod = 0;
        this.certificate = cert;
        this.untrusted = chain;
        this.crls = null;
        this.lastUntrusted = 0;
        this.otherContext = null;
        this.isValid = false;
        this.chain = null;
        this.error = 0;
        this.explicitPolicy = 0;
        this.errorDepth = 0;
        this.currentCertificate = null;
        this.currentIssuer = null;
        this.tree = null;

        this.verifyParameter = new VerifyParameter();

        if ( store != null ) {
            ret = verifyParameter.inherit(store.verifyParameter);
        } else {
            verifyParameter.flags |= X509Utils.X509_VP_FLAG_DEFAULT | X509Utils.X509_VP_FLAG_ONCE;
        }

        System.out.println("init: " + verifyParameter);

        if ( store != null ) {
            verifyCallback = store.getVerifyCallback();
            cleanup = store.cleanup;
        } else {
            cleanup = Store.CleanupFunction.EMPTY;
        }

        if ( ret != 0 ) {
            ret = verifyParameter.inherit(VerifyParameter.lookup("default"));
        }

        if ( ret == 0 ) {
            X509Error.addError(X509Utils.ERR_R_MALLOC_FAILURE);
            return 0;
        }

        this.checkIssued = defaultCheckIssued;
        this.getIssuer = getFirstIssuer;
        this.verifyCallback = nullCallback;
        this.verify = internalVerify;
        this.checkRevocation = defaultCheckRevocation;
        this.getCRL = defaultGetCRL;
        this.checkCRL = defaultCheckCRL;
        this.certificateCRL = defaultCertificateCRL;

        if ( store != null ) {
            if ( store.checkIssued != null && store.checkIssued != Store.CheckIssuedFunction.EMPTY ) {
                this.checkIssued = store.checkIssued;
            }
            if ( store.getIssuer != null && store.getIssuer != Store.GetIssuerFunction.EMPTY ) {
                this.getIssuer = store.getIssuer;
            }
            if ( store.verifyCallback != null && store.verifyCallback != Store.VerifyCallbackFunction.EMPTY ) {
                this.verifyCallback = store.verifyCallback;
            }
            if ( store.verify != null && store.verify != Store.VerifyFunction.EMPTY) {
                this.verify = store.verify;
            }
            if ( store.checkRevocation != null && store.checkRevocation != Store.CheckRevocationFunction.EMPTY) {
                this.checkRevocation = store.checkRevocation;
            }
            if ( store.getCRL != null && store.getCRL != Store.GetCRLFunction.EMPTY) {
                this.getCRL = store.getCRL;
            }
            if( store.checkCRL != null && store.checkCRL != Store.CheckCRLFunction.EMPTY) {
                this.checkCRL = store.checkCRL;
            }
            if ( store.certificateCRL != null && store.certificateCRL != Store.CertificateCRLFunction.EMPTY) {
                this.certificateCRL = store.certificateCRL;
            }
        }

        this.checkPolicy = defaultCheckPolicy;

        // getExtraData();
        return 1;
    }

    /**
     * c: X509_STORE_CTX_trusted_stack
     */
    public void trustedStack(List<X509AuxCertificate> sk) {
        otherContext = sk;
        getIssuer = getIssuerStack;
    }

    /**
     * c: X509_STORE_CTX_cleanup
     */
    public void cleanup() throws Exception {
        if (cleanup != null && cleanup != Store.CleanupFunction.EMPTY) {
            cleanup.call(this);
        }
        verifyParameter = null;
        tree = null;
        chain = null;
        extraData = null;
    }

    /**
     * c: find_issuer
     */
    public X509AuxCertificate findIssuer(final List<X509AuxCertificate> certs, final X509AuxCertificate cert) throws Exception {
        for ( X509AuxCertificate issuer : certs ) {
            if ( checkIssued.call(this, cert, issuer) != 0 ) {
                return issuer;
            }
        }
        return null;
    }

    public List<Object> getExtraData() {
        if ( this.extraData != null ) return this.extraData;
        ArrayList<Object> extraData = new ArrayList<Object>(8);
        extraData.add(null); extraData.add(null); extraData.add(null);
        extraData.add(null); extraData.add(null); extraData.add(null);
        return this.extraData = extraData;
    }

    /**
     * c: X509_STORE_CTX_set_ex_data
     */
    public int setExtraData(int idx, Object data) {
        getExtraData().set(idx, data);
        return 1;
    }

    /**
     * c: X509_STORE_CTX_get_ex_data
     */
    public Object getExtraData(int idx) {
        return getExtraData().get(idx);
    }

    /**
     * c: X509_STORE_CTX_get_error
     */
    public int getError() {
        return error;
    }

    /**
     * c: X509_STORE_CTX_set_error
     */
    public void setError(int s) {
        this.error = s;
    }

    /**
     * c: X509_STORE_CTX_get_error_depth
     */
    public int getErrorDepth() {
        return errorDepth;
    }

    /**
     * c: X509_STORE_CTX_get_current_cert
     */
    public X509AuxCertificate getCurrentCertificate() {
        return currentCertificate;
    }

    public X509CRL getCurrentCRL() {
        return currentCRL;
    }

    /**
     * c: X509_STORE_CTX_get_chain
     */
    public List<X509AuxCertificate> getChain() {
        return chain;
    }

    /**
     * c: X509_STORE_CTX_get1_chain
     */
    public List<X509AuxCertificate> getFirstChain() {
        if ( chain == null ) return null;
        return new ArrayList<X509AuxCertificate>(chain);
    }

    /**
     * c: X509_STORE_CTX_set_cert
     */
    public void setCertificate(X509AuxCertificate x) {
        this.certificate = x;
    }

    public void setCertificate(X509Certificate x) {
        this.certificate = ensureAux(x);
    }

    /**
     * c: X509_STORE_CTX_set_chain
     */
    public void setChain(List<X509Certificate> chain) {
        this.untrusted = ensureAux(chain);
    }

    public void setChain(X509Certificate[] sk) {
        this.untrusted = ensureAux(sk);
    }

    /**
     * c: X509_STORE_CTX_set0_crls
     */
    public void setCRLs(List<X509CRL> sk) {
        this.crls = sk;
    }

    /**
     * c: X509_STORE_CTX_set_purpose
     */
    public int setPurpose(int purpose) {
        return purposeInherit(0, purpose, 0);
    }

    /**
     * c: X509_STORE_CTX_set_trust
     */
    public int setTrust(int trust) {
        return purposeInherit(0, 0, trust);
    }

    /*
    private void resetSettingsToWithoutStore() {
        store = null;
        this.verifyParameter = new VerifyParameter();
        this.verifyParameter.flags |= X509Utils.X509_VP_FLAG_DEFAULT | X509Utils.X509_VP_FLAG_ONCE;
        this.verifyParameter.inherit(VerifyParameter.lookup("default"));
        this.cleanup = Store.CleanupFunction.EMPTY;
        this.checkIssued = defaultCheckIssued;
        this.getIssuer = getFirstIssuer;
        this.verifyCallback = nullCallback;
        this.verify = internalVerify;
        this.checkRevocation = defaultCheckRevocation;
        this.getCRL = defaultGetCRL;
        this.checkCRL = defaultCheckCRL;
        this.certificateCRL = defaultCertificateCRL;
    } */

    /**
     * c: SSL_CTX_load_verify_locations
     */
    /*
    public int loadVerifyLocations(Ruby runtime, String CAfile, String CApath) {
        boolean reset = false;
        try {
            if ( store == null ) {
                reset = true;
                store = new Store();
                this.verifyParameter.inherit(store.verifyParameter);
                verifyParameter.inherit(VerifyParameter.lookup("default"));
                this.cleanup = store.cleanup;
                if ( store.checkIssued != null && store.checkIssued != Store.CheckIssuedFunction.EMPTY ) {
                    this.checkIssued = store.checkIssued;
                }
                if ( store.getIssuer != null && store.getIssuer != Store.GetIssuerFunction.EMPTY ) {
                    this.getIssuer = store.getIssuer;
                }
                if ( store.verify != null && store.verify != Store.VerifyFunction.EMPTY ) {
                    this.verify = store.verify;
                }
                if ( store.verifyCallback != null && store.verifyCallback != Store.VerifyCallbackFunction.EMPTY ) {
                    this.verifyCallback = store.verifyCallback;
                }
                if ( store.checkRevocation != null && store.checkRevocation != Store.CheckRevocationFunction.EMPTY ) {
                    this.checkRevocation = store.checkRevocation;
                }
                if ( store.getCRL != null && store.getCRL != Store.GetCRLFunction.EMPTY ) {
                    this.getCRL = store.getCRL;
                }
                if ( store.checkCRL != null && store.checkCRL != Store.CheckCRLFunction.EMPTY ) {
                    this.checkCRL = store.checkCRL;
                }
                if ( store.certificateCRL != null && store.certificateCRL != Store.CertificateCRLFunction.EMPTY ) {
                    this.certificateCRL = store.certificateCRL;
                }
            }

            final int ret = store.loadLocations(runtime, CAfile, CApath);
            if ( ret == 0 && reset ) resetSettingsToWithoutStore();

            return ret;
        }
        catch (Exception e) {

            if ( reset ) resetSettingsToWithoutStore();
            return 0;
        }
    } */

    /**
     * c: X509_STORE_CTX_purpose_inherit
     */
    public int purposeInherit(int defaultPurpose,int purpose, int trust) {
        int idx;
        if(purpose == 0) {
            purpose = defaultPurpose;
        }
        if(purpose != 0) {
            idx = Purpose.getByID(purpose);
            if(idx == -1) {
                X509Error.addError(X509Utils.X509_R_UNKNOWN_PURPOSE_ID);
                return 0;
            }
            Purpose ptmp = Purpose.getFirst(idx);
            if(ptmp.trust == X509Utils.X509_TRUST_DEFAULT) {
                idx = Purpose.getByID(defaultPurpose);
                if(idx == -1) {
                    X509Error.addError(X509Utils.X509_R_UNKNOWN_PURPOSE_ID);
                    return 0;
                }
                ptmp = Purpose.getFirst(idx);
            }
            if(trust == 0) {
                trust = ptmp.trust;
            }
        }
        if(trust != 0) {
            idx = Trust.getByID(trust);
            if(idx == -1) {
                X509Error.addError(X509Utils.X509_R_UNKNOWN_TRUST_ID);
                return 0;
            }
        }

        if(purpose != 0 && verifyParameter.purpose == 0) {
            verifyParameter.purpose = purpose;
        }
        if(trust != 0 && verifyParameter.trust == 0) {
            verifyParameter.trust = trust;
        }
        return 1;
    }

    /**
     * c: X509_STORE_CTX_set_flags
     */
    public void setFlags(long flags) {
        verifyParameter.setFlags(flags);
    }

    /**
     * c: X509_STORE_CTX_set_time
     */
    public void setTime(long flags,Date t) {
        verifyParameter.setTime(t);
    }

    /**
     * c: X509_STORE_CTX_set_verify_cb
     */
    public void setVerifyCallback(Store.VerifyCallbackFunction verifyCallback) {
        this.verifyCallback = verifyCallback;
    }

    /**
     * c: X509_STORE_CTX_get0_policy_tree
     */
    PolicyTree getPolicyTree() {
        return tree;
    }

    /**
     * c: X509_STORE_CTX_get_explicit_policy
     */
    public int getExplicitPolicy() {
        return explicitPolicy;
    }

    /**
     * c: X509_STORE_CTX_get0_param
     */
    public VerifyParameter getParam() {
        return verifyParameter;
    }

    /**
     * c: X509_STORE_CTX_set0_param
     */
    public void setParam(VerifyParameter param) {
        this.verifyParameter = param;
    }

    /**
     * c: X509_STORE_CTX_set_default
     */
    public int setDefault(String name) {
        VerifyParameter p = VerifyParameter.lookup(name);
        if ( p == null ) return 0;
        return verifyParameter.inherit(p);
    }

    /**
     * c: X509_STORE_get_by_subject (it gets X509_STORE_CTX as the first parameter)
     */
    public int getBySubject(int type,Name name,X509Object[] ret) throws Exception {
        Store c = store;

        X509Object tmp = X509Object.retrieveBySubject(c.getObjects(),type,name);
        if ( tmp == null ) {
            List<Lookup> certificateMethods = c.getCertificateMethods();
            for(int i=currentMethod; i<certificateMethods.size(); i++) {
                Lookup lu = certificateMethods.get(i);
                X509Object[] stmp = new X509Object[1];
                int j = lu.bySubject(type,name,stmp);
                if ( j < 0 ) {
                    currentMethod = i;
                    return j;
                }
                else if( j > 0 ) {
                    tmp = stmp[0];
                    break;
                }
            }
            currentMethod = 0;

            if ( tmp == null ) return 0;
        }
        ret[0] = tmp;
        return 1;
    }

    /**
     * c: X509_verify_cert
     */
    public int verifyCertificate() throws Exception {

        if (Boolean.getBoolean("verify_new")) {
            return verifyCertificateNEW();
        }

        X509AuxCertificate x, xtmp = null, chain_ss = null;
        //X509_NAME xn;
        int bad_chain = 0, depth, i, num;

        if ( certificate == null ) {
            X509Error.addError(X509Utils.X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
            return -1;
        }

        // first we make sure the chain we are going to build is
        // present and that the first entry is in place

        if ( chain == null ) {
            chain = new ArrayList<X509AuxCertificate>();
            chain.add(certificate);
            lastUntrusted = 1;
        }

        // We use a temporary STACK so we can chop and hack at it

        List<X509AuxCertificate> sktmp = null;
        if ( untrusted != null ) {
            sktmp = new ArrayList<X509AuxCertificate>(untrusted);
            System.out.println("untrusted: " + untrusted.stream().map((c) -> c.getSubjectDN().toString()).collect(java.util.stream.Collectors.joining(",")));

            // XXX replace certs in untrusted with trusted versions if found
            X509Object[] objTmp = { null };
            for (ListIterator<X509AuxCertificate> iter = sktmp.listIterator(); iter.hasNext();) {
                X509AuxCertificate skCert = iter.next();
                Name principal = new Name(skCert.cert.getSubjectX500Principal());
                int ok = getBySubject(X509Utils.X509_LU_X509, principal, objTmp);
                if (ok == X509Utils.X509_LU_X509) {
                    // replace old with new and clear rest of untrusted
                    Certificate certificate = (Certificate) objTmp[0];
                    if (certificate.cert.equals(skCert)) {
                        iter.set(certificate.cert);
                        while (iter.hasNext()) {
                            iter.next();
                            iter.remove();
                        }
                        break;
                    }
                }
            }
            // XXX
        } else System.out.println("untrusted: " + null);

        num = chain.size();
        x = chain.get(num - 1);
        depth = verifyParameter.depth;
        for(;;) {

            System.out.println("num: " + num + " x: " + x.getSubjectDN() + " chain: " + chain.stream().map((c) -> c.getSubjectDN().toString()).collect(java.util.stream.Collectors.joining(",")));

            if ( depth < num ) break;

            if ( checkIssued.call(this, x, x) != 0 ) break;

            if ( sktmp != null ) {
                xtmp = findIssuer(sktmp, x);

                System.out.println(" findIssuer: " + (xtmp != null));

                if ( xtmp != null ) {
                    chain.add(xtmp);
                    sktmp.remove(xtmp);
                    lastUntrusted++;
                    x = xtmp;
                    num++;
                    continue;
                }
            }
            break;
        }

        // at this point, chain should contain a list of untrusted
        // certificates.  We now need to add at least one trusted one,
        // if possible, otherwise we complain.

        // Examine last certificate in chain and see if it is self signed.

        i = chain.size();
        x = chain.get(i - 1);

        if ( checkIssued.call(this, x, x) != 0 ) {
            // we have a self signed certificate
            if ( chain.size() == 1 ) {
                // We have a single self signed certificate: see if
                // we can find it in the store. We must have an exact
                // match to avoid possible impersonation.
                X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
                int ok = getIssuer.call(this, p_xtmp, x);
                xtmp = p_xtmp[0];
                if ( ok <= 0 || ! x.equals(xtmp) ) {
                    error = X509Utils.V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
                    currentCertificate = x;
                    errorDepth = i-1;
                    bad_chain = 1;
                    ok = verifyCallback.call(this, ZERO);
                    if ( ok == 0 ) return ok;
                } else {
                    // We have a match: replace certificate with store version
                    // so we get any trust settings.
                    x = xtmp;
                    chain.set(i-1,x);
                    lastUntrusted = 0;
                }
            } else {
                // extract and save self signed certificate for later use
                chain_ss = chain.remove(chain.size()-1);
                lastUntrusted--;
                num--;
                x = chain.get(num-1);
            }
        }
        // We now lookup certs from the certificate store
        for(;;) {
            // If we have enough, we break
            if ( depth < num ) break;
            //xn = new X509_NAME(x.getIssuerX500Principal());
            // If we are self signed, we break
            if ( checkIssued.call(this, x, x) != 0 ) break;

            X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
            int ok = getIssuer.call(this, p_xtmp, x);
            xtmp = p_xtmp[0];

            if ( ok < 0 ) return ok;
            if ( ok == 0 ) break;

            x = xtmp;
            chain.add(x);
            num++;
        }

        /* we now have our chain, lets check it... */

        //xn = new X509_NAME(x.getIssuerX500Principal());
        /* Is last certificate looked up self signed? */
        if ( checkIssued.call(this, x, x) == 0 ) {
            if ( chain_ss == null || checkIssued.call(this, x, chain_ss) == 0 ) {
                if(lastUntrusted >= num) {
                    error = X509Utils.V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
                } else {
                    error = X509Utils.V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                }
                currentCertificate = x;
            } else {
                chain.add(chain_ss);
                num++;
                lastUntrusted = num;
                currentCertificate = chain_ss;
                error = X509Utils.V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
            }
            errorDepth = num - 1;
            bad_chain = 1;
            int ok = verifyCallback.call(this, ZERO);
            if ( ok == 0 ) return ok;
        }

        // We have the chain complete: now we need to check its purpose
        int ok = checkChainExtensions();
        if ( ok == 0 ) return ok;

        /* TODO: Check name constraints (from 1.0.0) */

        // The chain extensions are OK: check trust
        if ( verifyParameter.trust > 0 ) ok = checkTrust();
        if ( ok == 0 ) return ok;

        // Check revocation status: we do this after copying parameters
        // because they may be needed for CRL signature verification.
        ok = checkRevocation.call(this);
        if ( ok == 0 ) return ok;

        /* At this point, we have a chain and need to verify it */
        if ( verify != null && verify != Store.VerifyFunction.EMPTY ) {
            ok = verify.call(this);
        } else {
            ok = internalVerify.call(this);
        }
        if ( ok == 0 ) return ok;

        /* TODO: RFC 3779 path validation, now that CRL check has been done (from 1.0.0) */

        /* If we get this far evaluate policies */
        if ( bad_chain == 0 && (verifyParameter.flags & X509Utils.V_FLAG_POLICY_CHECK) != 0 ) {
            ok = checkPolicy.call(this);
        }
        return ok;
    }

    /**
     * c: X509_verify_cert
     */
    public int verifyCertificateNEW() throws Exception {
        X509AuxCertificate x, xtmp = null, xtmp2, chain_ss = null;
        boolean bad_chain = false;
        int ok;
        boolean retry;
        int trust = X509_TRUST_UNTRUSTED;

        if (certificate == null) {
            addError(X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
            this.error = V_ERR_INVALID_CALL;
            return -1;
        }

        if (chain != null) {
            /*
             * This X509_STORE_CTX has already been used to verify a cert. We
             * cannot do another one.
             */
            addError(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            this.error = V_ERR_INVALID_CALL;
            return -1;
        }

        /*
         * first we make sure the chain we are going to build is present and that
         * the first entry is in place
         */
        //if (chain == null) {
            chain = new ArrayList<X509AuxCertificate>();
            chain.add(certificate);
        //}
        lastUntrusted = 1;

        /* We use a temporary STACK so we can chop and hack at it */
        LinkedList<X509AuxCertificate> sktmp = untrusted != null ?
                new LinkedList<>(untrusted) : null;
        ///
        if (untrusted != null) {
            System.out.println("untrusted: " + untrusted.stream().map((c) -> c.getSubjectDN().toString()).collect(java.util.stream.Collectors.joining(",")));
        } else System.out.println("untrusted: " + null);
        ///

        int num = chain.size();
        x = chain.get(num - 1);
        int depth = getParam().depth;

        System.out.println("verify (getParam().flags & V_FLAG_TRUSTED_FIRST): " + (getParam().flags & V_FLAG_TRUSTED_FIRST));

        for(;;) {

            System.out.println("num: " + num + " x: " + x.getSubjectDN() + " chain: " + chain.stream().map((c) -> c.getSubjectDN().toString()).collect(java.util.stream.Collectors.joining(",")));

            /* If we have enough, we break */
            if ( depth < num ) break;

            /* If we are self signed, we break */
            if ( checkIssued.call(this, x, x) != 0 ) break;

            /*
             * If asked see if we can find issuer in trusted store first
             */
//            if ((getParam().flags & V_FLAG_TRUSTED_FIRST) != 0) {
//                X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
//                ok = getIssuer.call(this, p_xtmp, x);
//                xtmp = p_xtmp[0];
//                if (ok < 0) {
//                    error = V_ERR_STORE_LOOKUP;
//                    return ok; // goto err;
//                }
//                /*
//                 * If successful for now free up cert so it will be picked up
//                 * again later.
//                 */
//                if (ok > 0) {
//                    xtmp = null;
//                    break;
//                }
//            }

            /* If we were passed a cert chain, use it first */
            if ( sktmp != null ) {
                xtmp = findIssuer(sktmp, x);

                System.out.println(" findIssuer: " + (xtmp != null));

                if ( xtmp != null ) {
                    chain.add(xtmp);
                    sktmp.remove(xtmp);
                    lastUntrusted++;
                    x = xtmp;
                    num++;
                    /*
                     * reparse the full chain for the next one
                     */
                    continue;
                }
            }
            break;
        }

        /* Remember how many untrusted certs we have */
        int j = num;
        /*
         * at this point, chain should contain a list of untrusted certificates.
         * We now need to add at least one trusted one, if possible, otherwise we
         * complain.
         */

        do {
            /*
             * Examine last certificate in chain and see if it is self signed.
             */
            int i = chain.size();
            x = chain.get(i - 1);
            if ( checkIssued.call(this, x, x) != 0 ) { // cert_self_signed(x)
                /* we have a self signed certificate */
                if ( chain.size() == 1 ) {
                    /*
                     * We have a single self signed certificate: see if we can
                     * find it in the store. We must have an exact match to avoid
                     * possible impersonation.
                     */
                    X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
                    ok = getIssuer.call(this, p_xtmp, x);
                    xtmp = p_xtmp[0];
                    if ( ok <= 0 || ! x.equals(xtmp) ) {
                        error = V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
                        currentCertificate = x;
                        errorDepth = i - 1;
                        bad_chain = true;
                        ok = verifyCallback.call(this, ZERO);
                        if ( ok == 0 ) return ok; // goto err;
                    } else {
                        /*
                         * We have a match: replace certificate with store
                         * version so we get any trust settings.
                         */
                        x = xtmp;
                        chain.set(i - 1, x);
                        lastUntrusted = 0;
                    }
                } else {
                    /*
                     * extract and save self signed certificate for later use
                     */
                    chain_ss = chain.remove(chain.size() - 1);
                    lastUntrusted--;
                    num--;
                    j--;
                    x = chain.get(num - 1);
                }
            }
            /* We now lookup certs from the certificate store */
            for(;;) {
                /* If we have enough, we break */
                if ( depth < num ) break;
                /* If we are self signed, we break */
                if ( checkIssued.call(this, x, x) != 0 ) break;
                X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
                ok = getIssuer.call(this, p_xtmp, x);
                xtmp = p_xtmp[0];

                if ( ok < 0 ) {
                    error = V_ERR_STORE_LOOKUP;
                    return ok; // goto err;
                }

                if ( ok == 0 ) break;

                x = xtmp;
                chain.add(x);
                num++;
            }

            /* we now have our chain, lets check it... */
            if ((trust = checkTrust()) == X509_TRUST_REJECTED) {
                /* Callback already issued */
                ok = 0;
                return ok; // goto err;
            }

            /*
             * If it's not explicitly trusted then check if there is an alternative
             * chain that could be used. We only do this if we haven't already
             * checked via TRUSTED_FIRST and the user hasn't switched off alternate
             * chain checking
             */
            retry = false;
            if (trust != X509_TRUST_TRUSTED
                    && (getParam().flags & V_FLAG_TRUSTED_FIRST) == 0
                    && (getParam().flags & V_FLAG_NO_ALT_CHAINS) == 0) {
                while (j-- > 1) {
                    xtmp2 = chain.get(j - 1);

                    X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
                    ok = getIssuer.call(this, p_xtmp, xtmp2);
                    xtmp = p_xtmp[0];

                    if (ok < 0) {
                        error = V_ERR_STORE_LOOKUP;
                        return ok; // goto err;
                    }
                    /* Check if we found an alternate chain */
                    if (ok > 0) {
                        /*
                         * Free up the found cert we'll add it again later
                         */
                        xtmp = null;

                        /*
                         * Dump all the certs above this point - we've found an
                         * alternate chain
                         */
                        while (num > j) {
                            chain.remove(chain.size() - 1);
                            num--;
                        }
                        lastUntrusted = chain.size();
                        retry = true;
                        break;
                    }
                }
            }
        } while (retry);

        /*
         * If not explicitly trusted then indicate error unless it's a single
         * self signed certificate in which case we've indicated an error already
         * and set bad_chain == 1
         */
        if (trust != X509_TRUST_TRUSTED && !bad_chain) {
            if (chain_ss == null || checkIssued.call(this, x, chain_ss) == 0) {
                System.out.println(" lastUntrusted: " + lastUntrusted + " num: " + num);
                if (lastUntrusted >= num) {
                    error = V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
                } else {
                    error = V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                }
                currentCertificate = x;
            } else {
                chain.add(chain_ss);
                num++;
                lastUntrusted = num;
                currentCertificate = chain_ss;
                error = V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
                chain_ss = null;
            }

            errorDepth = num - 1;
            bad_chain = true;
            ok = verifyCallback.call(this, ZERO);
            if ( ok == 0 ) return ok; // goto err;
        }

        /* We have the chain complete: now we need to check its purpose */
        ok = checkChainExtensions();
        if ( ok == 0 ) return ok; // goto err;

        /* TODO Check name constraints */
        //ok = check_name_constraints(ctx);
        //if ( ok == 0 ) return ok; // goto err;

        /* TODO not implemented - VerifyParameter needs to support id */
        //ok = check_id(ctx);
        //if ( ok == 0 ) return ok; // goto err;

        /*
         * Check revocation status: we do this after copying parameters because
         * they may be needed for CRL signature verification.
         */

        ok = checkRevocation.call(this);
        if ( ok == 0 ) return ok; // goto err;

        int err = chain_check_suiteb(this.errorDepth, null, this.chain, getParam().flags);
        if (err != V_OK) {
            error = err;
            currentCertificate = chain.get(errorDepth);
            ok = verifyCallback.call(this, ZERO);
            if ( ok == 0 ) return ok; // goto err;
        }

        /* At this point, we have a chain and need to verify it */
        if ( verify != null && verify != Store.VerifyFunction.EMPTY ) {
            ok = verify.call(this);
        } else {
            ok = internalVerify.call(this);
        }
        if ( ok == 0 ) return ok; // goto err;

        /* TODO: RFC 3779 path validation, now that CRL check has been done (from 1.0.0) */

        /* If we get this far evaluate policies */
        if (!bad_chain && (getParam().flags & V_FLAG_POLICY_CHECK) != 0) {
            ok = checkPolicy.call(this);
        }
        if ( ok == 0 ) return ok; // goto err;

        /* Safety net, error returns must set ctx->error */
        if (ok <= 0 && error == V_OK) {
            error = V_ERR_UNSPECIFIED;
        }
        return ok;
    }
    /*
0.10.8
1 ----
[#<OpenSSL::X509::Certificate
  subject=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
  issuer=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
  serial=#<OpenSSL::BN 85078157426496920958827089468591623647>,
  not_before=2020-10-07 19:21:40 UTC,
  not_after=2021-09-29 19:21:40 UTC>,
 #<OpenSSL::X509::Certificate
  subject=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
  issuer=#<OpenSSL::X509::Name CN=ISRG Root X1,O=Internet Security Research Group,C=US>,
  serial=#<OpenSSL::BN 192961496339968674994309121183282847578>,
  not_before=2020-09-04 00:00:00 UTC,
  not_after=2025-09-15 16:00:00 UTC>]
init: VerifyParameter{name='null', checkTime=null, inheritFlags=1, flags=0, purpose=0, trust=0, depth=-1, policies=null}
verify (getParam().flags & V_FLAG_TRUSTED_FIRST): 32768
verify num:1 x:   [0]         Version: 3
         SerialNumber: 435452651231011312001825766803379554023895
             IssuerDN: C=US,O=Let's Encrypt,CN=R3
           Start Date: Wed Aug 11 11:01:37 CEST 2021
           Final Date: Tue Nov 09 10:01:35 CET 2021
            SubjectDN: CN=geoip.elastic.dev
           Public Key: RSA Public Key [4a:0e:2e:27:0e:58:8e:2e:7c:9a:12:0b:74:10:a7:d9:85:f3:8e:da],[56:66:d1:a4]
        modulus: b5acf177fd85596d4ee5ebc79039cf8b8bdc6490c5c6cf15d2d948da9a5ffce4f29a504731bcc113706c5043fb4a44feea43e7a90a32f394baeb34f87f65f241f49651925e30f31c3839793f449710194abfe125458bebb14a6e73464765320cdfeb9e518e4cdd79a8f5aa3e2397af6a1af83dfd656915a11d12f315d2a2327eebd7fa977fe3f32aa665ccb9e07142ed5690936653a4ec2c2bb00c704d87457b56746f679b2acefddc685a8365770f662d08cbaa2dad463f5b01b05453bf55cf7a15dbe543967dfa774499d4a06de7ecae5c3c8e86f9f500191177c312ae1fe3d8c96ebf8ab6f9fafe025554a2cfe7f6f730d878e73e6da5865857f29a4b6c97
public exponent: 10001

  Signature Algorithm: SHA256withRSA
            Signature: 056145ca895b627caa0c0f1c914d0b9bb6ed08ce
                       fc09e9638cac550864ea8659ed26184734125c44
                       0af308192b7aced9e32c92889d6f4945cd56f188
                       4d50a2d9dff32794b1043a13e6ff088c46fdf0a1
                       ffffdbb725bd427ee1000e19c45178f27f819e22
                       24c7b5d297dfa8c6c1344edd821ae761ba1ce35b
                       3a740181cc27f05a5825d223dc2e7ca390315917
                       155506da085c6319c08b494490b09c738a5b1813
                       ec55a9cf9de467ed1b7366cba9771edf38ebdde7
                       53032b6ffae5b100b5eb782d75510dfc614278b5
                       3e51f146b927829943374a600855f0ffca32ef8a
                       c5697fbd29574260a753f1d7de8d23bd6c9aef0b
                       c6b857efc12b4eb4781a90e4c785bebb
       Extensions:
                       critical(true) KeyUsage: 0xa0
                       critical(false) 2.5.29.37 value = Sequence
    ObjectIdentifier(1.3.6.1.5.5.7.3.1)
    ObjectIdentifier(1.3.6.1.5.5.7.3.2)

                       critical(true) BasicConstraints: isCa(false)
                       critical(false) 2.5.29.14 value = DER Octet String[20]

                       critical(false) 2.5.29.35 value = Sequence
    Tagged [0] IMPLICIT
        DER Octet String[20]

                       critical(false) 1.3.6.1.5.5.7.1.1 value = Sequence
    Sequence
        ObjectIdentifier(1.3.6.1.5.5.7.48.1)
        Tagged [6] IMPLICIT
            DER Octet String[21]
    Sequence
        ObjectIdentifier(1.3.6.1.5.5.7.48.2)
        Tagged [6] IMPLICIT
            DER Octet String[22]

                       critical(false) 2.5.29.17 value = Sequence
    Tagged [2] IMPLICIT
        DER Octet String[17]

                       critical(false) 2.5.29.32 value = Sequence
    Sequence
        ObjectIdentifier(2.23.140.1.2.1)
    Sequence
        ObjectIdentifier(1.3.6.1.4.1.44947.1.1.1)
        Sequence
            Sequence
                ObjectIdentifier(1.3.6.1.5.5.7.2.1)
                IA5String(http://cps.letsencrypt.org)

                       critical(false) 1.3.6.1.4.1.11129.2.4.2 value = DER Octet String[242]


verify num:2 x:   [0]         Version: 3
         SerialNumber: 85078157426496920958827089468591623647
             IssuerDN: O=Digital Signature Trust Co.,CN=DST Root CA X3
           Start Date: Wed Oct 07 21:21:40 CEST 2020
           Final Date: Wed Sep 29 21:21:40 CEST 2021
            SubjectDN: C=US,O=Let's Encrypt,CN=R3
           Public Key: RSA Public Key [32:cd:42:71:87:db:2d:83:4c:25:a8:57:33:d1:97:cf:5e:ce:46:c2],[56:66:d1:a4]
        modulus: bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb15
public exponent: 10001

  Signature Algorithm: SHA256withRSA
            Signature: d94ce0c9f584883731dbbb13e2b3fc8b6b62126c
                       58b7497e3c02b7a81f2861ebcee02e73ef49077a
                       35841f1dad68f0d8fe56812f6d7f58a66e353610
                       1c73c3e5bd6d5e01d76e72fb2aa0b8d35764e55b
                       c269d4d0b2f77c4bc3178e887273dcfdfc6dbde3
                       c90b8e613a16587d74362b55803dc763be8443c6
                       39a10e6b579e3f29c180f6b2bd47cbaa306cb732
                       e159540b1809175e636cfb96673c1c730c938bc6
                       11762486de400707e47d2d66b525a39658c8ea80
                       eecf693b96fce68dc033f389f8292d14142d7ef0
                       6170955df70be5c0fb24faec8ecb61c8ee637128
                       a82c053b77ef9b5e0364f051d1e485535cb00297
                       d47ec634d2ce1000e4b1df3ac2ea17be
       Extensions:
                       critical(true) BasicConstraints: isCa(true), pathLenConstraint = 0
                       critical(true) KeyUsage: 0x86
                       critical(false) 1.3.6.1.5.5.7.1.1 value = Sequence
    Sequence
        ObjectIdentifier(1.3.6.1.5.5.7.48.2)
        Tagged [6] IMPLICIT
            DER Octet String[47]

                       critical(false) 2.5.29.35 value = Sequence
    Tagged [0] IMPLICIT
        DER Octet String[20]

                       critical(false) 2.5.29.32 value = Sequence
    Sequence
        ObjectIdentifier(2.23.140.1.2.1)
    Sequence
        ObjectIdentifier(1.3.6.1.4.1.44947.1.1.1)
        Sequence
            Sequence
                ObjectIdentifier(1.3.6.1.5.5.7.2.1)
                IA5String(http://cps.root-x1.letsencrypt.org)

                       critical(false) 2.5.29.31 value = Sequence
    Sequence
        Tagged [0]
            Tagged [0]
                Tagged [6] IMPLICIT
                    DER Octet String[43]

                       critical(false) 2.5.29.14 value = DER Octet String[20]

                       critical(false) 2.5.29.37 value = Sequence
    ObjectIdentifier(1.3.6.1.5.5.7.3.1)
    ObjectIdentifier(1.3.6.1.5.5.7.3.2)


 lastUntrusted: 2 num: 3
2 ----
[#<OpenSSL::X509::Certificate
  subject=#<OpenSSL::X509::Name CN=geoip.elastic.dev>,
  issuer=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
  serial=#<OpenSSL::BN 435452651231011312001825766803379554023895>,
  not_before=2021-08-11 09:01:37 UTC,
  not_after=2021-11-09 09:01:35 UTC>,
 #<OpenSSL::X509::Certificate
  subject=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
  issuer=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
  serial=#<OpenSSL::BN 85078157426496920958827089468591623647>,
  not_before=2020-10-07 19:21:40 UTC,
  not_after=2021-09-29 19:21:40 UTC>,
 #<OpenSSL::X509::Certificate
  subject=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
  issuer=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
  serial=#<OpenSSL::BN 91299735575339953335919266965803778155>,
  not_before=2000-09-30 21:12:19 UTC,
  not_after=2021-09-30 14:01:15 UTC>]
2
unable to get issuer certificate

     */

    /*
     * Given a STACK_OF(X509) find the issuer of cert (if any)
     *
     * x509_vfy.c: static int build_chain(X509_STORE_CTX *ctx)
     */
    private X509AuxCertificate find_issuer(List<X509AuxCertificate> sk, X509AuxCertificate x) throws Exception {
        X509AuxCertificate rv = null;

        for (X509AuxCertificate issuer : sk) {
            if (check_issued(x, issuer)) {
                rv = issuer;
                if (check_cert_time(rv)) break;
            }
        }
        return rv;
    }

    /*
     * Given a possible certificate and issuer check them
     *
     * x509_vfy.c: static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
     */
    private boolean check_issued(X509AuxCertificate x, X509AuxCertificate issuer) throws Exception {
        int ret;
        if (x == issuer) return checkIssued.call(this, x, x) != 0; // cert_self_signed(x)
        ret = checkIfIssuedBy(issuer, x);
        if (ret == V_OK) {
            /* Special case: single self signed certificate */
            boolean ss = checkIssued.call(this, x, x) != 0; // cert_self_signed(x)
            if (ss && chain.size() == 1) return true;

            //for (int i = 0; i < chain.size(); i++) {
            //    X509AuxCertificate ch = chain.get(i);
            //    if (ch == issuer || ch.equals(issuer)) {
            //        ret = V_ERR_PATH_LOOP;
            //        break;
            //    }
            //}
        }

        return (ret == V_OK);
    }

    private final static Set<String> CRITICAL_EXTENSIONS = new HashSet<String>(8);
    static {
        CRITICAL_EXTENSIONS.add("2.16.840.1.113730.1.1"); // netscape cert type, NID 71
        CRITICAL_EXTENSIONS.add("2.5.29.15"); // key usage, NID 83
        CRITICAL_EXTENSIONS.add("2.5.29.17"); // subject alt name, NID 85
        CRITICAL_EXTENSIONS.add("2.5.29.19"); // basic constraints, NID 87
        CRITICAL_EXTENSIONS.add("2.5.29.37"); // ext key usage, NID 126
        CRITICAL_EXTENSIONS.add("1.3.6.1.5.5.7.1.14"); // proxy cert info, NID 661
    }

    private static boolean supportsCriticalExtension(final String oid) {
        return CRITICAL_EXTENSIONS.contains(oid);
    }

    private static boolean unhandledCritical(final X509Extension ext) {
        final Set<String> criticalOIDs = ext.getCriticalExtensionOIDs();
        if ( criticalOIDs == null || criticalOIDs.size() == 0 ) {
            return false;
        }
        for ( final String oid : criticalOIDs ) {
            if ( ! supportsCriticalExtension(oid) ) return true;
        }
        return false;
    }

    /**
     * c: check_chain_extensions
     */
    public int checkChainExtensions() throws Exception {
        int ok, must_be_ca;
        X509AuxCertificate x;
        int proxy_path_length = 0;
        int allow_proxy_certs = (verifyParameter.flags & X509Utils.V_FLAG_ALLOW_PROXY_CERTS) != 0 ? 1 : 0;
        must_be_ca = -1;

        try {
            final String allowProxyCerts = System.getenv("OPENSSL_ALLOW_PROXY_CERTS");
            if ( allowProxyCerts != null && ! "false".equalsIgnoreCase(allowProxyCerts) ) {
                allow_proxy_certs = 1;
            }
        }
        catch (SecurityException e) { /* ignore if we can't use System.getenv */ }

        for (int i = 0; i < lastUntrusted; i++ ) {
            int ret;
            x = chain.get(i);
            if ( (verifyParameter.flags & X509Utils.V_FLAG_IGNORE_CRITICAL) == 0 && unhandledCritical(x) ) {
                error = X509Utils.V_ERR_UNHANDLED_CRITICAL_EXTENSION;
                errorDepth = i;
                currentCertificate = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }
            if ( allow_proxy_certs == 0 && x.getExtensionValue("1.3.6.1.5.5.7.1.14") != null ) {
                error = X509Utils.V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
                errorDepth = i;
                currentCertificate = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }

            ret = Purpose.checkCA(x);
            switch(must_be_ca) {
            case -1:
                if((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1 && ret != 0) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_CA;
                } else {
                    ret = 1;
                }
                break;
            case 0:
                if(ret != 0) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_NON_CA;
                } else {
                    ret = 1;
                }
                break;
            default:
                if(ret == 0 || ((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1)) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_CA;
                } else {
                    ret = 1;
                }
                break;
            }
            if(ret == 0) {
                errorDepth = i;
                currentCertificate = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }
            if(verifyParameter.purpose > 0) {
                ret = Purpose.checkPurpose(x,verifyParameter.purpose, must_be_ca > 0 ? 1 : 0);
                if(ret == 0 || ((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1)) {
                    error = X509Utils.V_ERR_INVALID_PURPOSE;
                    errorDepth = i;
                    currentCertificate = x;
                    ok = verifyCallback.call(this, ZERO);
                    if(ok == 0) {
                        return ok;
                    }
                }
            }

            if(i > 1 && x.getBasicConstraints() != -1 && x.getBasicConstraints() != Integer.MAX_VALUE && (i > (x.getBasicConstraints() + proxy_path_length + 1))) {
                error = X509Utils.V_ERR_PATH_LENGTH_EXCEEDED;
                errorDepth = i;
                currentCertificate = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }

            if(x.getExtensionValue("1.3.6.1.5.5.7.1.14") != null) {
                ASN1Sequence pci = (ASN1Sequence)new ASN1InputStream(x.getExtensionValue("1.3.6.1.5.5.7.1.14")).readObject();
                if(pci.size() > 0 && pci.getObjectAt(0) instanceof ASN1Integer) {
                    int pcpathlen = ((ASN1Integer)pci.getObjectAt(0)).getValue().intValue();
                    if(i > pcpathlen) {
                        error = X509Utils.V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
                        errorDepth = i;
                        currentCertificate = x;
                        ok = verifyCallback.call(this, ZERO);
                        if ( ok == 0 ) return ok;
                    }
                }
                proxy_path_length++;
                must_be_ca = 0;
            } else {
                must_be_ca = 1;
            }
        }
        return 1;
    }

    /**
     * c: X509_check_trust
     */
    public int checkTrust() throws Exception {
        int i, ok;
        X509AuxCertificate x;
        i = chain.size()-1;
        x = chain.get(i);
        ok = Trust.checkTrust(x, verifyParameter.trust, 0);
        if (ok == X509_TRUST_TRUSTED) return X509_TRUST_TRUSTED;
        errorDepth = 1;
        currentCertificate = x;
        if (ok == X509_TRUST_REJECTED) {
            error = V_ERR_CERT_REJECTED;

            ok = verifyCallback.call(this, ZERO);
            if (ok == 0) return X509_TRUST_REJECTED;
        } else {
            error = V_ERR_CERT_UNTRUSTED;
        }
        return X509_TRUST_UNTRUSTED;
    }

//    private int check_trust() throws Exception {
//        int i, ok;
//        X509AuxCertificate x;
//
//        /* Check all trusted certificates in chain */
//        for (i = this.lastUntrusted; i < this.chain.size(); i++) {
//            x = chain.get(i);
//            ok = Trust.checkTrust(x, getParam().trust, 0);
//            /* If explicitly trusted return trusted */
//            if (ok == X509_TRUST_TRUSTED) return X509_TRUST_TRUSTED;
//            /*
//             * If explicitly rejected notify callback and reject if not
//             * overridden.
//             */
//            if (ok == X509_TRUST_REJECTED) {
//                this.errorDepth = i;
//                this.currentCertificate = x;
//                this.error = V_ERR_CERT_REJECTED;
//                ok = verifyCallback.call(this, ZERO);
//                if (ok == 0) return X509_TRUST_REJECTED;
//            }
//        }
//        /*
//         * If we accept partial chains and have at least one trusted certificate
//         * return success.
//         */
//        if ((getParam().flags & V_FLAG_PARTIAL_CHAIN) != 0) {
//            X509AuxCertificate mx;
//            if (this.lastUntrusted < this.chain.size()) {
//                return X509_TRUST_TRUSTED;
//            }
//            x = chain.get(0);
//            mx = lookup_cert_match(ctx, x);
//            if (mx != null) {
//                this.chain.set(0, mx);
//                this.lastUntrusted = 0;
//                return X509_TRUST_TRUSTED;
//            }
//        }
//
//        /*
//         * If no trusted certs in chain at all return untrusted and allow
//         * standard (no issuer cert) etc errors to be indicated.
//         */
//        return X509_TRUST_UNTRUSTED;
//    }

    /**
     * c: check_cert_time
     */
    boolean check_cert_time(X509AuxCertificate x) throws Exception {
        final Date pTime;
        if ( (verifyParameter.flags & X509Utils.V_FLAG_USE_CHECK_TIME) != 0 ) {
            pTime = this.verifyParameter.checkTime;
        } else {
            pTime = Calendar.getInstance().getTime();
        }

        if ( ! x.getNotBefore().before(pTime) ) {
            error = X509Utils.V_ERR_CERT_NOT_YET_VALID;
            currentCertificate = x;
            if ( verifyCallback.call(this, ZERO) == 0 ) {
                return false;
            }
        }
        if ( ! x.getNotAfter().after(pTime) ) {
            error = X509Utils.V_ERR_CERT_HAS_EXPIRED;
            currentCertificate = x;
            if ( verifyCallback.call(this, ZERO) == 0 ) {
                return false;
            }
        }
        return true;
    }

    //private static final int CRLDP_ALL_REASONS = 0x807f;

    /**
     * c: check_cert
     */
    public int checkCertificate() throws Exception {
        final X509CRL[] crl = new X509CRL[1];
        X509AuxCertificate x;
        int ok, cnum;
        cnum = errorDepth;
        x = chain.get(cnum);
        this.currentCertificate = x;
        this.currentIssuer = null;
        //this.current_crl_score = 0;
        //this.current_reasons = 0;

        //while (this.current_reasons != CRLDP_ALL_REASONS) {
            //int last_reasons = this.current_reasons;
            /* Try to retrieve relevant CRL */
            ok = getCRL.call(this, crl, x);
            /*
             * If error looking up CRL, nothing we can do except notify callback
             */
            if (ok == 0) {
                this.error = V_ERR_UNABLE_TO_GET_CRL;
                ok = verifyCallback.call(this, ZERO);
                this.currentCRL = null; // goto err;
                return ok;
            }
            this.currentCRL = crl[0];
            ok = checkCRL.call(this, crl[0]);
            if (ok == 0) {
                this.currentCRL = null; // goto err;
                return ok;
            }
            //ok = 1;
            /* Don't look in full CRL if delta reason is removefromCRL */
            //if (ok != 2) {
                ok = certificateCRL.call(this, crl[0], x);
                if (ok == 0) {
                    this.currentCRL = null; // goto err;
                    return ok;
                }
            //}
            /*
             * If reasons not updated we wont get anywhere by another iteration,
             * so exit loop.
             */
            //if (last_reasons == this.current_reasons) {
            //    this.error = V_ERR_UNABLE_TO_GET_CRL;
            //    ok = verifyCallback.call(this, ZERO);
            //    break; // goto err;
            //}
        //}

        this.currentCRL = null;
        return ok;
    }

    /**
     * c: check_crl_time
     */
    public int checkCRLTime(X509CRL crl, int notify) throws Exception {
        currentCRL = crl;
        final Date pTime;
        if ( (verifyParameter.flags & X509Utils.V_FLAG_USE_CHECK_TIME) != 0 ) {
            pTime = this.verifyParameter.checkTime;
        } else {
            pTime = Calendar.getInstance().getTime();
        }

        if ( ! crl.getThisUpdate().before(pTime) ) {
            error = X509Utils.V_ERR_CRL_NOT_YET_VALID;
            if ( notify == 0 || verifyCallback.call(this, ZERO) == 0 ) {
                return 0;
            }
        }
        if ( crl.getNextUpdate() != null && !crl.getNextUpdate().after(pTime) ) {
            error = X509Utils.V_ERR_CRL_HAS_EXPIRED;
            if ( notify == 0 || verifyCallback.call(this, ZERO) == 0 ) {
                return 0;
            }
        }

        currentCRL = null;
        return 1;
    }

    /*
     * x509_cmp.c: int X509_chain_check_suiteb(int *perror_depth, X509 *x, STACK_OF(X509) *chain, unsigned long flags)
     */
    private static int chain_check_suiteb(int perror_depth, X509AuxCertificate x, List<X509AuxCertificate> chain, long flags) {
        return 0;
    }

    /**
     * c: get_crl_sk
     */
    public int getCRLStack(X509CRL[] pcrl, Name name, List<X509CRL> crls) throws Exception {
        X509CRL bestCrl = null;
        if ( crls != null ) {
            for ( final X509CRL crl : crls ) {
                if( ! name.equalTo( crl.getIssuerX500Principal() ) ) {
                    continue;
                }
                if ( checkCRLTime(crl, 0) != 0 ) {
                    pcrl[0] = crl;
                    return 1;
                }
                bestCrl = crl;
            }
        }
        if ( bestCrl != null ) {
            pcrl[0] = bestCrl;
        }
        return 0;
    }

    final static Store.GetIssuerFunction getFirstIssuer = new Store.GetIssuerFunction() {
        public int call(StoreContext context, X509AuxCertificate[] issuer, X509AuxCertificate cert) throws Exception {
            return context.getFirstIssuer(issuer, cert);
        }
    };

    /**
     * c: get_issuer_sk
     */
    final static Store.GetIssuerFunction getIssuerStack = new Store.GetIssuerFunction() {
        public int call(StoreContext context, X509AuxCertificate[] issuer, X509AuxCertificate x) throws Exception {
            issuer[0] = context.findIssuer(context.otherContext, x);
            if ( issuer[0] != null ) {
                return 1;
            } else {
                return 0;
            }
        }
    };

    /**
     * c: check_issued
     */
    final static Store.CheckIssuedFunction defaultCheckIssued = new Store.CheckIssuedFunction() {
        public int call(StoreContext context, X509AuxCertificate cert, X509AuxCertificate issuer) throws Exception {
            int ret = X509Utils.checkIfIssuedBy(issuer, cert);
            if ( ret == X509Utils.V_OK ) return 1;

            if ( (context.verifyParameter.flags & X509Utils.V_FLAG_CB_ISSUER_CHECK) == 0 ) {
                return 0;
            }
            context.error = ret;
            context.currentCertificate = cert;
            context.currentIssuer = issuer;

            return context.verifyCallback.call(context, ZERO);
        }
    };

    /**
     * c: null_callback
     */
    final static Store.VerifyCallbackFunction nullCallback = new Store.VerifyCallbackFunction() {
        public int call(StoreContext context, Integer outcome) {
            return outcome.intValue();
        }
    };

    /**
     * c: internal_verify
     */
    final static Store.VerifyFunction internalVerify = new Store.VerifyFunction() {
        public int call(final StoreContext context) throws Exception {
            Store.VerifyCallbackFunction verifyCallback = context.verifyCallback;

            int n = context.chain.size();
            context.errorDepth = n - 1;
            n--;
            X509AuxCertificate xi = context.chain.get(n);
            X509AuxCertificate xs = null;
            int ok;

            if ( context.checkIssued.call(context,xi,xi) != 0 ) {
                xs = xi;
            }
            else {
                if ( n <= 0 ) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
                    context.currentCertificate = xi;
                    ok = verifyCallback.call(context, ZERO);
                    return ok;
                }
                else {
                    n--;
                    context.errorDepth = n;
                    xs = context.chain.get(n);
                }
            }

            while ( n >= 0 ) {
                context.errorDepth = n;
                if ( ! xs.isValid() ) {
                    try {
                        xs.verify(xi.getPublicKey());
                    }
                    catch(Exception e) {
                        /*
                        System.err.println("n: " + n);
                        System.err.println("verifying: " + xs);
                        System.err.println("verifying with issuer?: " + xi);
                        System.err.println("verifying with issuer.key?: " + xi.getPublicKey());
                        System.err.println("exception: " + e);
                        */
                        context.error = X509Utils.V_ERR_CERT_SIGNATURE_FAILURE;
                        context.currentCertificate = xs;
                        ok = verifyCallback.call(context, ZERO);
                        if ( ok == 0 ) return ok;
                    }
                }

                xs.setValid(true);
                if (context.check_cert_time(xs) == false) return 0; // ok = 0;

                context.currentIssuer = xi;
                context.currentCertificate = xs;
                ok = verifyCallback.call(context, Integer.valueOf(1));
                if ( ok == 0 ) return ok;

                n--;
                if ( n >= 0 ) {
                    xi = xs;
                    xs = context.chain.get(n);
                }
            }
            ok = 1;
            return ok;
        }
    };

    /**
     * x509_vfy.c: static int check_revocation(X509_STORE_CTX *ctx)
     */
    final static Store.CheckRevocationFunction defaultCheckRevocation = new Store.CheckRevocationFunction() {
        public int call(final StoreContext ctx) throws Exception {
            if ( (ctx.getParam().flags & X509Utils.V_FLAG_CRL_CHECK) == 0 ) {
                return 1;
            }
            final int last;
            if ( (ctx.verifyParameter.flags & X509Utils.V_FLAG_CRL_CHECK_ALL) != 0 ) {
                last = ctx.chain.size() - 1;
            }
            else {
                last = 0;
            }
            int ok;
            for ( int i = 0; i<=last; i++ ) {
                ctx.errorDepth = i;
                ok = ctx.checkCertificate();
                if ( ok == 0 ) return 0;
            }
            return 1;
        }
    };

    /**
     * c: get_crl
     */
    final static Store.GetCRLFunction defaultGetCRL = new Store.GetCRLFunction() {
        public int call(final StoreContext context, final X509CRL[] crls, X509AuxCertificate x) throws Exception {
            final Name name = new Name( x.getIssuerX500Principal() );
            final X509CRL[] crl = new X509CRL[1];
            int ok = context.getCRLStack(crl, name, context.crls);
            if ( ok != 0 ) {
                crls[0] = crl[0];
                return 1;
            }
            final X509Object[] xobj = new X509Object[1];
            ok = context.getBySubject(X509Utils.X509_LU_CRL, name, xobj);
            if ( ok == 0 ) {
                if ( crl[0] != null ) {
                    crls[0] = crl[0];
                    return 1;
                }
                return 0;
            }
            crls[0] = (X509CRL) ( (CRL) xobj[0] ).crl;
            return 1;
        }
    };

    /**
     * c: check_crl
     */
    final static Store.CheckCRLFunction defaultCheckCRL = new Store.CheckCRLFunction() {
        public int call(final StoreContext context, final X509CRL crl) throws Exception {
            final int errorDepth = context.errorDepth;
            final int lastInChain = context.chain.size() - 1;

            int ok;
            final X509AuxCertificate issuer;
            if ( errorDepth < lastInChain ) {
                issuer = context.chain.get(errorDepth + 1);
            }
            else {
                issuer = context.chain.get(lastInChain);
                if ( context.checkIssued.call(context,issuer,issuer) == 0 ) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_GET_CRL_ISSUER;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
            }

            if ( issuer != null ) {
                if ( issuer.getKeyUsage() != null && ! issuer.getKeyUsage()[6] ) {
                    context.error = X509Utils.V_ERR_KEYUSAGE_NO_CRL_SIGN;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
                final PublicKey ikey = issuer.getPublicKey();
                if ( ikey == null ) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
                else {
                    try {
                        SecurityHelper.verify(crl, ikey);
                    }
                    catch (GeneralSecurityException ex) {
                        context.error = X509Utils.V_ERR_CRL_SIGNATURE_FAILURE;
                        ok = context.verifyCallback.call(context, ZERO);
                        if ( ok == 0 ) return ok;
                    }
                }
            }

            ok = context.checkCRLTime(crl, 1);
            if ( ok == 0 ) return ok;

            return 1;
        }
    };

    /**
     * c: cert_crl
     */
    final static Store.CertificateCRLFunction defaultCertificateCRL = new Store.CertificateCRLFunction() {
        public int call(final StoreContext context, final X509CRL crl, X509AuxCertificate x) throws Exception {
            int ok;
            if ( crl.getRevokedCertificate( x.getSerialNumber() ) != null ) {
                context.error = X509Utils.V_ERR_CERT_REVOKED;
                ok = context.verifyCallback.call(context, ZERO);
                if ( ok == 0 ) return 0;
            }
            if ( (context.verifyParameter.flags & X509Utils.V_FLAG_IGNORE_CRITICAL) != 0 ) {
                return 1;
            }
            if ( crl.getCriticalExtensionOIDs() != null && crl.getCriticalExtensionOIDs().size() > 0 ) {
                context.error = X509Utils.V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION;
                ok = context.verifyCallback.call(context, ZERO);
                if ( ok == 0 ) return 0;
            }
            return 1;
        }
    };

    /**
     * c: check_policy
     */
    final static CheckPolicyFunction defaultCheckPolicy = new CheckPolicyFunction() {
        public int call(StoreContext context) throws Exception {
            return 1;
        }
    };
}// X509_STORE_CTX
