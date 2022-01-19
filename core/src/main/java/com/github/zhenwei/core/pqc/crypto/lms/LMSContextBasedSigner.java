package com.github.zhenwei.core.pqc.crypto.lms;

import org.bouncycastle.pqc.crypto.lms.LMSContext;

public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);

    long getUsagesRemaining();
}