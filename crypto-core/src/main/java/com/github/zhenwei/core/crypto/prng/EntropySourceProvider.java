package com.github.zhenwei.core.crypto.prng;

public interface EntropySourceProvider {

  EntropySource get(final int bitsRequired);
}