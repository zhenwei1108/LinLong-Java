package com.github.zhenwei.core.pqc.crypto.sphincsplus;

import java.security.SecureRandom;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPair;
import com.github.zhenwei.core.crypto.AsymmetricCipherKeyPairGenerator;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;

public class SPHINCSPlusKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;
    private SPHINCSPlusParameters parameters;

    public void init(KeyGenerationParameters param)
    {
        random = param.getRandom();
        parameters = ((SPHINCSPlusKeyGenerationParameters)param).getParameters();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SPHINCSPlusEngine engine = parameters.getEngine();

        SK sk = new SK(sec_rand(engine.N), sec_rand(engine.N));
        byte[] pkSeed = sec_rand(engine.N);
        // TODO
        PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).htPubKey);

        return new AsymmetricCipherKeyPair(new SPHINCSPlusPublicKeyParameters(parameters, pk),
                            new SPHINCSPlusPrivateKeyParameters(parameters, sk, pk));
    }

    private byte[] sec_rand(int n)
    {
        byte[] rv = new byte[n];

        random.nextBytes(rv);

        return rv;
    }
}