package com.github.zhenwei.core.pqc.crypto.mceliece;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;

public class McElieceCCA2KeyGenerationParameters
    extends KeyGenerationParameters
{
    private McElieceCCA2Parameters params;

    public McElieceCCA2KeyGenerationParameters(
        SecureRandom random,
        McElieceCCA2Parameters params)
    {
        // XXX key size?
        super(random, 128);
        this.params = params;
    }

    public McElieceCCA2Parameters getParameters()
    {
        return params;
    }
}