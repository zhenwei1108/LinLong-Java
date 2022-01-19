package com.github.zhenwei.core.util.test;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * A fixed secure random designed to return data for someone needing random bytes.
 */
public class TestRandomData
    extends FixedSecureRandom
{
    /**
     * Constructor from a Hex encoding of the data.
     *
     * @param encoding a Hex encoding of the data to be returned.
     */
    public TestRandomData(String encoding)
    {
        super(new Source[] { new Data(Hex.decode(encoding)) });
    }

    /**
     * Constructor from an array of bytes.
     *
     * @param encoding a byte array representing the data to be returned.
     */
    public TestRandomData(byte[] encoding)
    {
        super(new Source[] { new Data(encoding) });
    }
}