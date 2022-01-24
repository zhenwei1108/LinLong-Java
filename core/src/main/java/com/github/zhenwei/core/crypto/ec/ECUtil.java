package com.github.zhenwei.core.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import com.github.zhenwei.core.math.ec.ECConstants;
import com.github.zhenwei.core.util.BigIntegers;

class ECUtil
{
    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k;
        do
        {
            k = BigIntegers.createRandomBigInteger(nBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));
        return k;
    }
}