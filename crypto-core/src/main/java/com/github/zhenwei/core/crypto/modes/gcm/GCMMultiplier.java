package com.github.zhenwei.core.crypto.modes.gcm;

public interface GCMMultiplier {

  void init(byte[] H);

  void multiplyH(byte[] x);
}