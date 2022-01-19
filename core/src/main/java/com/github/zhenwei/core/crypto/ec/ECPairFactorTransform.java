package com.github.zhenwei.core.crypto.ec;

import java.math.BigInteger;
import org.bouncycastle.crypto.ec.ECPairTransform;

public interface ECPairFactorTransform
    extends ECPairTransform
{
    /**
     * Return the last value used to calculated a transform.
     *
     * @return a BigInteger representing the last transform value used.
     */
    BigInteger getTransformValue();
}