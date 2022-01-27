package com.github.zhenwei.sdk.enums;

/**
 * @description: 非对称算法,模长
 * @author: zhangzhenwei
 * @date: 2022/1/25 22:57
 */
public enum KeyAlgEnum {
  SM2_256("EC",256),
  RSA_1024("RSA",1024),
  RSA_2048("RSA",2048),

  ;


  private String alg;
  private int keyLen;

  KeyAlgEnum(String alg, int keyLen) {
    this.alg = alg;
    this.keyLen = keyLen;
  }

  public String getAlg() {
    return alg;
  }

  public int getKeyLen() {
    return keyLen;
  }
}