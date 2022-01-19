package com.github.zhenwei.core.math.ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.ec.endo.ECEndomorphism;

public interface GLVEndomorphism extends ECEndomorphism
{
    BigInteger[] decomposeScalar(BigInteger k);
}