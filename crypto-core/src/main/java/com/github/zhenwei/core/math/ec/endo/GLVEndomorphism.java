package com.github.zhenwei.core.math.ec.endo;

import java.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism {

  BigInteger[] decomposeScalar(BigInteger k);
}