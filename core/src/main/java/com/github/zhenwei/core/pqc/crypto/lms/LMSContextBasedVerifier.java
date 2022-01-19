package com.github.zhenwei.core.pqc.crypto.lms;

import org.bouncycastle.pqc.crypto.lms.LMSContext;

public interface LMSContextBasedVerifier
{
    LMSContext generateLMSContext(byte[] signature);

    boolean verify(LMSContext context);
}