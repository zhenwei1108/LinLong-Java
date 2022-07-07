package com.github.zhenwei.pkix.its;

import com.github.zhenwei.pkix.util.oer.its.PublicEncryptionKey;
import com.github.zhenwei.pkix.util.oer.its.SymmAlgorithm;

public class ITSPublicEncryptionKey {

  protected final PublicEncryptionKey encryptionKey;

  public ITSPublicEncryptionKey(PublicEncryptionKey encryptionKey) {
    this.encryptionKey = encryptionKey;
  }

  public enum symmAlgorithm {
    aes128Ccm(SymmAlgorithm.aes128Ccm.intValueExact());

    private final int tagValue;

    symmAlgorithm(int tagValue) {
      this.tagValue = tagValue;
    }
  }

  public PublicEncryptionKey toASN1Structure() {
    return encryptionKey;
  }
}