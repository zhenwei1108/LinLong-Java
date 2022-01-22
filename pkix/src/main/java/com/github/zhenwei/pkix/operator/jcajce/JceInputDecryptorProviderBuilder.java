package com.github.zhenwei.pkix.operator.jcajce;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.cryptopro.GOST28147Parameters;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.InputStream;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;



/**
 * A generic decryptor provider for IETF style algorithms.
 */
public class JceInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JceInputDecryptorProviderBuilder()
    {
    }

    public org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Build a decryptor provider which will use the passed in bytes for the symmetric key.
     *
     * @param keyBytes bytes representing the key to use.
     * @return an decryptor provider.
     */
    public InputDecryptorProvider build(byte[] keyBytes)
    {
        final byte[] encKeyBytes = Arrays.clone(keyBytes);

        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                encryptionAlg = algorithmIdentifier;

                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    cipher = helper.createCipher(algorithm.getId());
                    SecretKey key = new SecretKeySpec(encKeyBytes, algorithm.getId());
                    
                    ASN1Encodable encParams = algorithmIdentifier.getParameters();

                    if (encParams instanceof ASN1OctetString)
                    {
                        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                    }
                    else
                    {
                        // TODO: at the moment it's just GOST, but...
                        GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                        cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                    }
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return encryptionAlg;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, cipher);
                    }
                };
            }
        };
    }
}