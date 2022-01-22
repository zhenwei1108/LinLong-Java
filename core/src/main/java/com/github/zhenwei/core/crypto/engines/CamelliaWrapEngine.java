package com.github.zhenwei.core.crypto.engines;

/**
 * An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
 * <p>
 * For further details see: <a href="https://www.ietf.org/rfc/rfc3657.txt">https://www.ietf.org/rfc/rfc3657.txt</a>.
 */
public class CamelliaWrapEngine
    extends RFC3394WrapEngine
{
    public CamelliaWrapEngine()
    {
        super(new CamelliaEngine());
    }
}