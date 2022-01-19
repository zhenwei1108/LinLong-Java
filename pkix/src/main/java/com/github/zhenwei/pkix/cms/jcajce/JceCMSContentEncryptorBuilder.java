package com.github.zhenwei.pkix.cms.jcajce;

import java.io.OutputStream;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.EnvelopedDataHelper;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCaptureStream;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.SecretKeySizeProvider;
import org.bouncycastle.operator.jcajce.JceGenericKey;

/**
 * Builder for the content encryptor in EnvelopedData - used to encrypt the actual transmitted content.
 */
public class JceCMSContentEncryptorBuilder
{
    private static final SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private SecureRandom random;
    private AlgorithmIdentifier algorithmIdentifier;
    private AlgorithmParameters algorithmParameters;

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID));
    }

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;

        int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

        if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC))
        {
            if (keySize != 168 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 168;
        }
        else if (encryptionOID.equals(OIWObjectIdentifiers.desCBC))
        {
            if (keySize != 56 && keySize != fixedSize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 56;
        }
        else
        {
            if (fixedSize > 0 && fixedSize != keySize)
            {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = keySize;
        }
    }

    /**
     * Constructor for a content encryptor builder based on an algorithm identifier and its contained parameters.
     *
     * @param encryptionAlgId the full algorithm identifier for the encryption.
     */
    public JceCMSContentEncryptorBuilder(AlgorithmIdentifier encryptionAlgId)
    {
        this(encryptionAlgId.getAlgorithm(), KEY_SIZE_PROVIDER.getKeySize(encryptionAlgId.getAlgorithm()));
        this.algorithmIdentifier = encryptionAlgId;
    }

    /**
     * Set the provider to use for content encryption.
     *
     * @param provider the provider object to use for cipher and default parameters creation.
     * @return the current builder instance.
     */
    public org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    /**
     * Set the provider to use for content encryption (by name)
     *
     * @param providerName the name of the provider to use for cipher and default parameters creation.
     * @return the current builder instance.
     */
    public org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

        return this;
    }

    /**
     * Provide a specified source of randomness to be used for session key and IV/nonce generation.
     *
     * @param random the secure random to use.
     * @return the current builder instance.
     */
    public org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    /**
     * Provide a set of algorithm parameters for the content encryption cipher to use.
     *
     * @param algorithmParameters algorithmParameters for content encryption.
     * @return the current builder instance.
     */
    public org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder setAlgorithmParameters(AlgorithmParameters algorithmParameters)
    {
        this.algorithmParameters = algorithmParameters;

        return this;
    }

    public OutputEncryptor build()
        throws CMSException
    {
        if (algorithmParameters != null)
        {
            if (helper.isAuthEnveloped(encryptionOID))
            {
                return new CMSAuthOutputEncryptor(encryptionOID, keySize, algorithmParameters, random);
            }
            return new CMSOutputEncryptor(encryptionOID, keySize, algorithmParameters, random);
        }
        if (algorithmIdentifier != null)
        {
            ASN1Encodable params = algorithmIdentifier.getParameters();
            if (params != null && !params.equals(DERNull.INSTANCE))
            {
                try
                {
                    algorithmParameters = helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());

                    algorithmParameters.init(params.toASN1Primitive().getEncoded());
                }
                catch (Exception e)
                {
                    throw new CMSException("unable to process provided algorithmIdentifier: " + e.toString(), e);
                }
            }
        }

        if (helper.isAuthEnveloped(encryptionOID))
        {
            return new CMSAuthOutputEncryptor(encryptionOID, keySize, algorithmParameters, random);
        }
        return new CMSOutputEncryptor(encryptionOID, keySize, algorithmParameters, random);
    }

    private class CMSOutputEncryptor
        implements OutputEncryptor
    {
        private SecretKey encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Cipher              cipher;

        CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            KeyGenerator keyGen = helper.createKeyGenerator(encryptionOID);

            random = CryptoServicesRegistrar.getSecureRandom(random);

            if (keySize < 0)
            {
                keyGen.init(random);
            }
            else
            {
                keyGen.init(keySize, random);
            }

            cipher = helper.createCipher(encryptionOID);
            encKey = keyGen.generateKey();

            if (params == null)
            {
                params = helper.generateParameters(encryptionOID, encKey, random);
            }

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
            }

            //
            // If params are null we try and second guess on them as some providers don't provide
            // algorithm parameter generation explicitly but instead generate them under the hood.
            //
            if (params == null)
            {
                params = cipher.getParameters();
            }

            algorithmIdentifier = helper.getAlgorithmIdentifier(encryptionOID, params);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return new CipherOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new JceGenericKey(algorithmIdentifier, encKey);
        }
    }

    private class CMSAuthOutputEncryptor
        implements OutputAEADEncryptor
    {
        private SecretKey encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Cipher              cipher;
        private MacCaptureStream    macOut;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters params, SecureRandom random)
            throws CMSException
        {
            KeyGenerator keyGen = helper.createKeyGenerator(encryptionOID);

            random = CryptoServicesRegistrar.getSecureRandom(random);

            if (keySize < 0)
            {
                keyGen.init(random);
            }
            else
            {
                keyGen.init(keySize, random);
            }

            cipher = helper.createCipher(encryptionOID);
            encKey = keyGen.generateKey();

            if (params == null)
            {
                params = helper.generateParameters(encryptionOID, encKey, random);
            }

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
            }

            //
            // If params are null we try and second guess on them as some providers don't provide
            // algorithm parameter generation explicitly but instead generate them under the hood.
            //
            if (params == null)
            {
                params = cipher.getParameters();
            }

            algorithmIdentifier = helper.getAlgorithmIdentifier(encryptionOID, params);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            // TODO: works for CCM too, but others will follow.
            GCMParameters p = GCMParameters.getInstance(algorithmIdentifier.getParameters());

            macOut = new MacCaptureStream(dOut, p.getIcvLen());
            return new CipherOutputStream(macOut, cipher);
        }

        public GenericKey getKey()
        {
            return new JceGenericKey(algorithmIdentifier, encKey);
        }

        public OutputStream getAADStream()
        {
            if (checkForAEAD())
            {
                return new JceAADStream(cipher);
            }

            return null; // TODO: okay this is awful, we could use AEADParameterSpec for earlier JDKs.
        }

        public byte[] getMAC()
        {
            return macOut.getMac();
        }
    }

    private static boolean checkForAEAD()
    {
        return (Boolean)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                try
                {
                    return Cipher.class.getMethod("updateAAD", byte[].class) != null;
                }
                catch (Exception ignore)
                {
                    // TODO[logging] Log the fact that we are falling back to BC-specific class
                    return Boolean.FALSE;
                }
            }
        });
    }
}