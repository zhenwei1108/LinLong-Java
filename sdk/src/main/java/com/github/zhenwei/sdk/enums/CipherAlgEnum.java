package com.github.zhenwei.sdk.enums;

public enum CipherAlgEnum {
  SM2("SM2"),
  RSA("RSA/ECB/PKCS1Padding"),
  SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding"),
  SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding", true),

  ;

  private String alg;
  /**
   * 是否需要初始化向量
   */
  private boolean isNeedIv;

  CipherAlgEnum(String alg, boolean isNeedIv) {
    this.alg = alg;
    this.isNeedIv = isNeedIv;
  }


  CipherAlgEnum(String alg) {
    this.alg = alg;
    this.isNeedIv = false;
  }

  public String getAlg() {
    return alg;
  }

  public boolean isNeedIv() {
    return isNeedIv;
  }
}