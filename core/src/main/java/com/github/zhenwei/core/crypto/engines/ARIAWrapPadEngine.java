package com.github.zhenwei.core.crypto.engines;

import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;

public class ARIAWrapPadEngine
    extends RFC5649WrapEngine
{
    public ARIAWrapPadEngine()
    {
        super(new ARIAEngine());
    }
}