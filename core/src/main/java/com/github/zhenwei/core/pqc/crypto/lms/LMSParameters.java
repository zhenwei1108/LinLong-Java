package com.github.zhenwei.core.pqc.crypto.lms;

import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

public class LMSParameters
{
    private final LMSigParameters lmSigParam;
    private final LMOtsParameters lmOTSParam;

    public LMSParameters(LMSigParameters lmSigParam, LMOtsParameters lmOTSParam)
    {
        this.lmSigParam = lmSigParam;
        this.lmOTSParam = lmOTSParam;
    }

    public LMSigParameters getLMSigParam()
    {
        return lmSigParam;
    }

    public LMOtsParameters getLMOTSParam()
    {
        return lmOTSParam;
    }
}