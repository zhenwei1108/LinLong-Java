package com.github.zhenwei.core.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;

public class RainbowKeyGenerationParameters
    extends KeyGenerationParameters
{
    private RainbowParameters params;

    public RainbowKeyGenerationParameters(
        SecureRandom random,
        RainbowParameters params)
    {
        // TODO: key size?
        super(random, params.getVi()[params.getVi().length - 1] - params.getVi()[0]);
        this.params = params;
    }

    public RainbowParameters getParameters()
    {
        return params;
    }
}