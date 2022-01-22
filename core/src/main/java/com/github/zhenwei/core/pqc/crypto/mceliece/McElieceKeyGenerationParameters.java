package com.github.zhenwei.core.pqc.crypto.mceliece;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;
 

public class McElieceKeyGenerationParameters
    extends KeyGenerationParameters
{
    private McElieceParameters params;

    public McElieceKeyGenerationParameters(
        SecureRandom random,
        McElieceParameters params)
    {
        // XXX key size?
        super(random, 256);
        this.params = params;
    }

    public McElieceParameters getParameters()
    {
        return params;
    }
}