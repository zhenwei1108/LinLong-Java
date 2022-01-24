package com.github.zhenwei.core.pqc.crypto.lms;

import java.security.SecureRandom;
import com.github.zhenwei.core.crypto.KeyGenerationParameters;

public class HSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters[] lmsParameters;

    /**
     * Base constructor - parameters and a source of randomness.
     *
     * @param lmsParameters array of LMS parameters, one per level in the hierarchy (up to 8 levels).
     * @param random   the random byte source.
     */
    public HSSKeyGenerationParameters(
        LMSParameters[] lmsParameters,
        SecureRandom random)
    {
        super(random, LmsUtils.calculateStrength(lmsParameters[0]));
        if (lmsParameters.length == 0 || lmsParameters.length > 8)  // RFC 8554, Section 6.
        {
            throw new IllegalArgumentException("lmsParameters length should be between 1 and 8 inclusive");
        }
        this.lmsParameters = lmsParameters;
    }

    public int getDepth()
    {
        return lmsParameters.length;
    }

    public LMSParameters[] getLmsParameters()
    {
        return lmsParameters;
    }
}