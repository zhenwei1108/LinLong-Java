package com.github.zhenwei.pkix.pkcs.jcajce;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.cryptopro.GOST28147Parameters;
import com.github.zhenwei.core.asn1.misc.MiscObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PBES2Parameters;
import com.github.zhenwei.core.asn1.pkcs.PBKDF2Params;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.provider.jcajce.spec.PBKDF2KeySpec;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import  ScryptParams;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.jcajce.PBKDF1Key;
  
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.SecretKeySizeProvider;
import PBEParameter;





public class JcePKCSPBEInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private boolean      wrongPKCS12Zero = false;
    private SecretKeySizeProvider keySizeProvider = DefaultSecretKeySizeProvider.INSTANCE;

    public JcePKCSPBEInputDecryptorProviderBuilder()
    {
    }

    public org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder setTryWrongPKCS12Zero(boolean tryWrong)
    {
        this.wrongPKCS12Zero = tryWrong;

        return this;
    }

    /**
     * Set the lookup provider of AlgorithmIdentifier returning key_size_in_bits used to
     * handle PKCS5 decryption.
     *
     * @param keySizeProvider  a provider of integer secret key sizes.
     *
     * @return the current builder.
     */
    public org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder setKeySizeProvider(SecretKeySizeProvider keySizeProvider)
    {
        this.keySizeProvider = keySizeProvider;

        return this;
    }

    public InputDecryptorProvider build(final char[] password)
    {
        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                SecretKey key;
                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
                    {
                        PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, wrongPKCS12Zero, pbeParams.getIV(), pbeParams.getIterations().intValue()));

                        encryptionAlg = algorithmIdentifier;
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
                    {
                        PBES2Parameters alg = PBES2Parameters.getInstance(algorithmIdentifier.getParameters());

                        if (MiscObjectIdentifiers.id_scrypt.equals(alg.getKeyDerivationFunc().getAlgorithm()))
                        {
                            ScryptParams params = ScryptParams.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            SecretKeyFactory keyFact = helper.createSecretKeyFactory("SCRYPT");

                            key = keyFact.generateSecret(new ScryptKeySpec(password,
                                       params.getSalt(), params.getCostParameter().intValue(), params.getBlockSize().intValue(),
                                       params.getParallelizationParameter().intValue(), keySizeProvider.getKeySize(encScheme)));
                        }
                        else
                        {
                            SecretKeyFactory keyFact = helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
                            PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
                            AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                            if (func.isDefaultPrf())
                            {
                                key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), func.getIterationCount().intValue(), keySizeProvider.getKeySize(encScheme)));
                            }
                            else
                            {
                                key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), func.getIterationCount().intValue(), keySizeProvider.getKeySize(encScheme), func.getPrf()));
                            }
                        }

                        cipher = helper.createCipher(alg.getEncryptionScheme().getAlgorithm().getId());

                        encryptionAlg = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

                        ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
                        if (encParams instanceof ASN1OctetString)
                        {
                            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                        }
                        else if (encParams instanceof ASN1Sequence && isCCMorGCM(alg.getEncryptionScheme()))
                        {
                            AlgorithmParameters params = AlgorithmParameters.getInstance(alg.getEncryptionScheme().getAlgorithm().getId());

                            params.init(((ASN1Sequence)encParams).getEncoded());

                            cipher.init(Cipher.DECRYPT_MODE, key, params);
                        }
                        else if (encParams == null) // absent parameters
                        {
                            cipher.init(Cipher.DECRYPT_MODE, key);
                        }
                        else
                        {
                            // TODO: at the moment it's just GOST, but...
                            GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                            cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                        }
                    }
                    else if (algorithm.equals(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC)
                        || algorithm.equals(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC))
                    {
                        PBEParameter pbeParams = PBEParameter.getInstance(algorithmIdentifier.getParameters());

                        cipher = helper.createCipher(algorithm.getId());

                        cipher.init(Cipher.DECRYPT_MODE, new PBKDF1Key(password, PasswordConverter.ASCII),
                                new PBEParameterSpec(pbeParams.getSalt(), pbeParams.getIterationCount().intValue()));
                    }
                    else
                    {
                        throw new OperatorCreationException("unable to create InputDecryptor: algorithm " + algorithm + " unknown.");
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

    private boolean isCCMorGCM(ASN1Encodable encParams)
    {
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(encParams);
        ASN1Encodable params = algId.getParameters();

        if (params instanceof ASN1Sequence)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(params);
            if (seq.size() == 2)
            {
                return seq.getObjectAt(1) instanceof ASN1Integer;
            }
        }

        return false;
    }
}