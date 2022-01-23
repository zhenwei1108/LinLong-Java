package com.github.zhenwei.core.crypto.ec;


import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.math.ec.ECPoint;

public interface ECEncryptor {

  void init(CipherParameters params);

  ECPair encrypt(ECPoint point);
}