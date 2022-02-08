package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.ec.BCECPublicKey;
import java.security.PublicKey;

public class HashBuilder {

  public byte[] sm3Digest(PublicKey publicKey, byte[] source) {
    SM3Digest digest = new SM3Digest();
    ;
    if (publicKey instanceof BCECPublicKey) {
      BCECPublicKey key = (BCECPublicKey) publicKey;
      digest.init(key.getParameters().getCurve(), key.getParameters().getG(), key.getQ());
    }
    byte[] hash = new byte[digest.getDigestSize()];
    digest.update(source, 0, source.length);
    digest.doFinal(hash, 0);
    return hash;
  }


}