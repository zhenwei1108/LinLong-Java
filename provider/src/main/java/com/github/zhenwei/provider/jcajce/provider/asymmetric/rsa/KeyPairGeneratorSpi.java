package com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa;


import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.params.RSAPrivateCrtKeyParameters;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import RSAKeyPairGenerator;
 
 
 
 


public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final AlgorithmIdentifier PKCS_ALGID = new AlgorithmIdentifier(
        PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier PSS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);

    final static BigInteger defaultPublicExponent = BigInteger.valueOf(0x10001);

    RSAKeyGenerationParameters param;
    RSAKeyPairGenerator engine;
    AlgorithmIdentifier algId;

    public KeyPairGeneratorSpi(
        String algorithmName,
        AlgorithmIdentifier algId)
    {
        super(algorithmName);

        this.algId = algId;
        engine = new RSAKeyPairGenerator();
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
        engine.init(param);
    }

    public KeyPairGeneratorSpi()
    {
        this("RSA", PKCS_ALGID);
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        param = new RSAKeyGenerationParameters(defaultPublicExponent,
            random, strength, PrimeCertaintyCalculator.getDefaultCertainty(strength));

        engine.init(param);
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof RSAKeyGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rsaParams = (RSAKeyGenParameterSpec)params;

        param = new RSAKeyGenerationParameters(
            rsaParams.getPublicExponent(),
            random, rsaParams.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));

        engine.init(param);
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

        return new KeyPair(new BCRSAPublicKey(algId, pub),
            new BCRSAPrivateCrtKey(algId, priv));
    }

    public static class PSS
        extends rsa.KeyPairGeneratorSpi
    {
        public PSS()
        {
            super("RSASSA-PSS", PSS_ALGID);
        }
    }
}