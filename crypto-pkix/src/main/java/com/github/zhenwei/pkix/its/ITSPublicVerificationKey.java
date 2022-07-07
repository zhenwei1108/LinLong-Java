package com.github.zhenwei.pkix.its;

import com.github.zhenwei.pkix.util.oer.its.PublicVerificationKey;

public class ITSPublicVerificationKey {

  protected final PublicVerificationKey verificationKey;

  public ITSPublicVerificationKey(PublicVerificationKey encryptionKey) {
    this.verificationKey = encryptionKey;
  }

  public PublicVerificationKey toASN1Structure() {
    return verificationKey;
  }
}