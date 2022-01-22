package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;
 
 

public class DSAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DSAParameters    params;

    public DSAKeyGenerationParameters(
        SecureRandom    random,
        DSAParameters   params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public DSAParameters getParameters()
    {
        return params;
    }
}