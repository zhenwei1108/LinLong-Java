package com.github.zhenwei.provider.jcajce.provider.keystore.jks;

import sun.security.util.Debug;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

public class WeGooKeyStoreDelegator extends KeyStoreSpi  {
    private static final String KEYSTORE_TYPE_COMPAT = "keystore.type.compat";
    private static final Debug debug = Debug.getInstance("keystore");
    private final String primaryType;
    private final String secondaryType;
    private final Class<? extends KeyStoreSpi> primaryKeyStore;
    private final Class<? extends KeyStoreSpi> secondaryKeyStore;
    private String type;
    private KeyStoreSpi keystore;
    private boolean compatModeEnabled = true;

    public WeGooKeyStoreDelegator(String var1, Class<? extends KeyStoreSpi> var2, String var3, Class<? extends KeyStoreSpi> var4) {
        this.compatModeEnabled = "true".equalsIgnoreCase((String) AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                return Security.getProperty("keystore.type.compat");
            }
        }));
        if (this.compatModeEnabled) {
            this.primaryType = var1;
            this.secondaryType = var3;
            this.primaryKeyStore = var2;
            this.secondaryKeyStore = var4;
        } else {
            this.primaryType = var1;
            this.secondaryType = null;
            this.primaryKeyStore = var2;
            this.secondaryKeyStore = null;
            if (debug != null) {
                debug.println("WARNING: compatibility mode disabled for " + var1 + " and " + var3 + " keystore types");
            }
        }

    }

    public Key engineGetKey(String var1, char[] var2) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return this.keystore.engineGetKey(var1, var2);
    }

    public Certificate[] engineGetCertificateChain(String var1) {
        return this.keystore.engineGetCertificateChain(var1);
    }

    public Certificate engineGetCertificate(String var1) {
        return this.keystore.engineGetCertificate(var1);
    }

    public Date engineGetCreationDate(String var1) {
        return this.keystore.engineGetCreationDate(var1);
    }

    public void engineSetKeyEntry(String var1, Key var2, char[] var3, Certificate[] var4) throws KeyStoreException {
        this.keystore.engineSetKeyEntry(var1, var2, var3, var4);
    }

    public void engineSetKeyEntry(String var1, byte[] var2, Certificate[] var3) throws KeyStoreException {
        this.keystore.engineSetKeyEntry(var1, var2, var3);
    }

    public void engineSetCertificateEntry(String var1, Certificate var2) throws KeyStoreException {
        this.keystore.engineSetCertificateEntry(var1, var2);
    }

    public void engineDeleteEntry(String var1) throws KeyStoreException {
        this.keystore.engineDeleteEntry(var1);
    }

    public Enumeration<String> engineAliases() {
        return this.keystore.engineAliases();
    }

    public boolean engineContainsAlias(String var1) {
        return this.keystore.engineContainsAlias(var1);
    }

    public int engineSize() {
        return this.keystore.engineSize();
    }

    public boolean engineIsKeyEntry(String var1) {
        return this.keystore.engineIsKeyEntry(var1);
    }

    public boolean engineIsCertificateEntry(String var1) {
        return this.keystore.engineIsCertificateEntry(var1);
    }

    public String engineGetCertificateAlias(Certificate var1) {
        return this.keystore.engineGetCertificateAlias(var1);
    }

    public KeyStore.Entry engineGetEntry(String var1, KeyStore.ProtectionParameter var2) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return this.keystore.engineGetEntry(var1, var2);
    }

    public void engineSetEntry(String var1, KeyStore.Entry var2, KeyStore.ProtectionParameter var3) throws KeyStoreException {
        this.keystore.engineSetEntry(var1, var2, var3);
    }

    public boolean engineEntryInstanceOf(String var1, Class<? extends KeyStore.Entry> var2) {
        return this.keystore.engineEntryInstanceOf(var1, var2);
    }

    public void engineStore(OutputStream var1, char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (debug != null) {
            debug.println("Storing keystore in " + this.type + " format");
        }

        this.keystore.engineStore(var1, var2);
    }

    public void engineLoad(InputStream var1, char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (var1 != null && this.compatModeEnabled) {
            BufferedInputStream var3 = new BufferedInputStream(var1);
            var3.mark(2147483647);

            try {
                this.keystore = (KeyStoreSpi)this.primaryKeyStore.newInstance();
                this.type = this.primaryType;
                this.keystore.engineLoad(var3, var2);
            } catch (Exception var9) {
                if (var9 instanceof IOException && var9.getCause() instanceof UnrecoverableKeyException) {
                    throw (IOException)var9;
                }

                try {
                    this.keystore = (KeyStoreSpi)this.secondaryKeyStore.newInstance();
                    this.type = this.secondaryType;
                    var3.reset();
                    this.keystore.engineLoad(var3, var2);
                    if (debug != null) {
                        debug.println("WARNING: switching from " + this.primaryType + " to " + this.secondaryType + " keystore file format has altered the keystore security level");
                    }
                } catch (IllegalAccessException | InstantiationException var7) {
                } catch (NoSuchAlgorithmException | CertificateException | IOException var8) {
                    if (var8 instanceof IOException && var8.getCause() instanceof UnrecoverableKeyException) {
                        throw (IOException)var8;
                    }

                    if (var9 instanceof IOException) {
                        throw (IOException)var9;
                    }

                    if (var9 instanceof CertificateException) {
                        throw (CertificateException)var9;
                    }

                    if (var9 instanceof NoSuchAlgorithmException) {
                        throw (NoSuchAlgorithmException)var9;
                    }
                }
            }

            if (debug != null) {
                debug.println("Loaded a keystore in " + this.type + " format");
            }
        } else {
            try {
                this.keystore = (KeyStoreSpi)this.primaryKeyStore.newInstance();
            } catch (IllegalAccessException | InstantiationException var6) {
            }

            this.type = this.primaryType;
            if (debug != null && var1 == null) {
                debug.println("Creating a new keystore in " + this.type + " format");
            }

            this.keystore.engineLoad(var1, var2);
        }

    }
}