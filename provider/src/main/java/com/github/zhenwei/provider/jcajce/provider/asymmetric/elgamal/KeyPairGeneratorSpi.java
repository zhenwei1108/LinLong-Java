package com.github.zhenwei.provider.jcajce.provider.asymmetric.elgamal;

import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.CryptoServicesRegistrar;
import com.github.zhenwei.core.crypto.params.ElGamalParameters;
import com.github.zhenwei.core.crypto.params.ElGamalPrivateKeyParameters;
import com.github.zhenwei.provider.jce.provider.BouncyCastleProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import ElGamalKeyPairGenerator;
import ElGamalParametersGenerator;
import ElGamalKeyGenerationParameters;
 
import ElGamalParameterSpec;

;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    ElGamalKeyGenerationParameters param;
    ElGamalKeyPairGenerator engine = new ElGamalKeyPairGenerator();
    int strength = 1024;
    int certainty = 20;
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("ElGamal");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof ElGamalParameterSpec) && !(params instanceof DHParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec or an ElGamalParameterSpec");
        }

        if (params instanceof ElGamalParameterSpec)
        {
            ElGamalParameterSpec elParams = (ElGamalParameterSpec)params;

            param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(elParams.getP(), elParams.getG()));
        }
        else
        {
            DHParameterSpec dhParams = (DHParameterSpec)params;

            param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
        }

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            DHParameterSpec dhParams = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(strength);

            if (dhParams != null)
            {
                param = new ElGamalKeyGenerationParameters(random, new ElGamalParameters(dhParams.getP(), dhParams.getG(), dhParams.getL()));
            }
            else
            {
                ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();

                pGen.init(strength, certainty, random);
                param = new ElGamalKeyGenerationParameters(random, pGen.generateParameters());
            }

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCElGamalPublicKey(pub),
            new BCElGamalPrivateKey(priv));
    }
}