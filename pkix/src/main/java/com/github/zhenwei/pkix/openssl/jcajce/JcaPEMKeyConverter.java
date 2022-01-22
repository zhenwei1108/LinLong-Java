package com.github.zhenwei.pkix.openssl.jcajce;




import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;

import pkcs.PrivateKeyInfo;
import x9.X9ObjectIdentifiers;

public class JcaPEMKeyConverter
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    private static final Map algorithms = new HashMap();

    static
    {
        algorithms.put(X9ObjectIdentifiers.id_ecPublicKey, "ECDSA");
        algorithms.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        algorithms.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    public org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public KeyPair getKeyPair(PEMKeyPair keyPair)
        throws PEMException
    {
        try
        {
            KeyFactory keyFactory = getKeyFactory(keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm());

            return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())),
                                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws PEMException
    {
        try
        {
            KeyFactory keyFactory = getKeyFactory(publicKeyInfo.getAlgorithm());

            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws PEMException
    {
        try
        {
            KeyFactory keyFactory = getKeyFactory(privateKeyInfo.getPrivateKeyAlgorithm());

            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    private KeyFactory getKeyFactory(AlgorithmIdentifier algId)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        ASN1ObjectIdentifier algorithm =  algId.getAlgorithm();

        String algName = (String)algorithms.get(algorithm);

        if (algName == null)
        {
            algName = algorithm.getId();
        }

        try
        {
            return helper.createKeyFactory(algName);
        }
        catch (NoSuchAlgorithmException e)
        {
            if (algName.equals("ECDSA"))
            {
                return helper.createKeyFactory("EC"); // try a fall back
            }

            throw e;
        }
    }
}