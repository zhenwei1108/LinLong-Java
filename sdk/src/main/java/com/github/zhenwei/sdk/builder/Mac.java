package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.BlockCipher;
import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.digests.*;
import com.github.zhenwei.core.crypto.engines.AESEngine;
import com.github.zhenwei.core.crypto.engines.SM4Engine;
import com.github.zhenwei.core.crypto.macs.CMac;
import com.github.zhenwei.core.crypto.macs.HMac;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.enums.DigestAlgEnum;
import com.github.zhenwei.core.enums.KeyEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;

import java.security.Key;

public class Mac {


  public byte[] hmac(DigestAlgEnum digestAlgEnum, Key key, byte[] source) {
    Digest digest;
    switch (digestAlgEnum) {
      case SHA1: digest = new SHA1Digest(); break;
      case SHA224: digest = new SHA224Digest(); break;
      case SHA256: digest = new SHA256Digest(); break;
      case SHA384: digest = new SHA384Digest(); break;
      case SHA512: digest = new SHA512Digest(); break;
      //default sm3 digest
      default: digest = new SM3Digest(); break;
    }
    HMac hMac = new HMac(digest);
    hMac.init(new KeyParameter(key.getEncoded()));
    hMac.update(source, 0, source.length);
    byte[] result = new byte[hMac.getMacSize()];
    hMac.doFinal(result, 0);
    return result;
  }

  public byte[] cmac(KeyEnum alg, byte[] key, byte[] source) throws WeGooCryptoException {
    BlockCipher engine;
    switch (alg){
      case AES_128:
      case AES_256:
        engine = new AESEngine();break;
      default: engine = new SM4Engine();
    }
    CMac cMac = new CMac(engine);
    cMac.init(new KeyParameter(key));
    cMac.update(source, 0 , source.length);
    byte[] result = new byte[cMac.getMacSize()];
    cMac.doFinal(result,0);
    return result;
  }

}