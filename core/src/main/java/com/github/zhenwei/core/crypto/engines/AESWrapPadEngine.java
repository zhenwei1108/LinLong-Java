package com.github.zhenwei.core.crypto.engines;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;

public class AESWrapPadEngine
    extends RFC5649WrapEngine
{
    public AESWrapPadEngine()
    {
        super(new AESEngine());
    }
}