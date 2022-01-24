package com.github.zhenwei.provider.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2Parameters;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import com.github.zhenwei.core.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import com.github.zhenwei.provider.jcajce.spec.McElieceCCA2KeyGenParameterSpec;

public class McElieceCCA2KeyPairGeneratorSpi
    extends KeyPairGenerator
{
    private McElieceCCA2KeyPairGenerator kpg;

    public McElieceCCA2KeyPairGeneratorSpi()
    {
        super("McEliece-CCA2");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        kpg = new McElieceCCA2KeyPairGenerator();

        McElieceCCA2KeyGenParameterSpec ecc = (McElieceCCA2KeyGenParameterSpec)params;

        McElieceCCA2KeyGenerationParameters mccca2KGParams = new McElieceCCA2KeyGenerationParameters(
            random, new McElieceCCA2Parameters(ecc.getM(), ecc.getT(), ecc.getDigest()));
        kpg.init(mccca2KGParams);
    }

    public void initialize(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        kpg = new McElieceCCA2KeyPairGenerator();

        McElieceCCA2KeyGenParameterSpec ecc = (McElieceCCA2KeyGenParameterSpec)params;

        McElieceCCA2KeyGenerationParameters mccca2KGParams = new McElieceCCA2KeyGenerationParameters(
            CryptoServicesRegistrar.getSecureRandom(), new McElieceCCA2Parameters(ecc.getM(), ecc.getT(), ecc.getDigest()));
        kpg.init(mccca2KGParams);
    }

    public void initialize(int keySize, SecureRandom random)
    {
        kpg = new McElieceCCA2KeyPairGenerator();

        McElieceCCA2KeyGenerationParameters mccca2KGParams = new McElieceCCA2KeyGenerationParameters(random, new McElieceCCA2Parameters());
        kpg.init(mccca2KGParams);
    }

    public KeyPair generateKeyPair()
    {
        AsymmetricCipherKeyPair generateKeyPair = kpg.generateKeyPair();
        McElieceCCA2PrivateKeyParameters sk = (McElieceCCA2PrivateKeyParameters)generateKeyPair.getPrivate();
        McElieceCCA2PublicKeyParameters pk = (McElieceCCA2PublicKeyParameters)generateKeyPair.getPublic();

        return new KeyPair(new BCMcElieceCCA2PublicKey(pk), new BCMcElieceCCA2PrivateKey(sk));
    }
}