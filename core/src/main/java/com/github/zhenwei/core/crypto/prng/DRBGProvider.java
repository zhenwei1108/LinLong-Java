package com.github.zhenwei.core.crypto.prng;


import com.github.zhenwei.core.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider {

  String getAlgorithm();

  SP80090DRBG get(EntropySource entropySource);
}