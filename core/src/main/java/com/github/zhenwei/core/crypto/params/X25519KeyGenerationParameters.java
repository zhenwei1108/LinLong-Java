package com.github.zhenwei.core.crypto.params;

import java.security.SecureRandom;
 

public class X25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 255);
    }
}