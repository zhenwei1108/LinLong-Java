package com.github.zhenwei.core.crypto.params;

import com.github.zhenwei.core.crypto.KeyGenerationParameters;
import java.security.SecureRandom;
 

public class Ed25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 256);
    }
}