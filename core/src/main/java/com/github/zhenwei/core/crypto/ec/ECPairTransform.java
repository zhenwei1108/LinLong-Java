package com.github.zhenwei.core.crypto.ec;

import com.github.zhenwei.core.crypto.CipherParameters;

public interface ECPairTransform {

  void init(CipherParameters params);

  ECPair transform(ECPair cipherText);
}