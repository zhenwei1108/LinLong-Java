package com.github.zhenwei.core.crypto.params;

import java.security.SecureRandom;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;

public class Ed448KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed448KeyGenerationParameters(SecureRandom random)
    {
        super(random, 448);
    }
}