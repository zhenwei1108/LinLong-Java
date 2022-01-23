package com.github.zhenwei.core.pqc.crypto.newhope;

import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.engines.ChaChaEngine;


class ChaCha20 {

  static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len) {
    ChaChaEngine e = new ChaChaEngine(20);
    e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
    e.processBytes(buf, off, len, buf, off);
  }
}