package org.sdk.crypto.enums;

public enum  SymmetryCipherEnum {
  SM4_ECB_PKCS5("SM4/ECB/PKCS5Padding"),
  SM4_CBC_PKCS5("SM4/CBC/PKCS5Padding"),
  SM4_CCM_NONE("SM4/CCM/NoPadding"),
  SM4_GCM_NONE("SM4/GCM/NoPadding"),
  ;

  private String cipherAlg;

  SymmetryCipherEnum(String cipherAlg) {
    this.cipherAlg = cipherAlg;
  }

  public String getCipherAlg() {
    return cipherAlg;
  }
}
