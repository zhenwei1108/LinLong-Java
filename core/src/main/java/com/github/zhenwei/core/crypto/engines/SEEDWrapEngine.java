package com.github.zhenwei.core.crypto.engines;

import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;

/**
 * An implementation of the SEED key wrapper based on RFC 4010/RFC 3394.
 * <p>
 * For further details see: <a href="https://www.ietf.org/rfc/rfc4010.txt">https://www.ietf.org/rfc/rfc4010.txt</a>.
 */
public class SEEDWrapEngine
    extends RFC3394WrapEngine
{
    public SEEDWrapEngine()
    {
        super(new SEEDEngine());
    }
}