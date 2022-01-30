package com.github.zhenwei.sdk.enums;

import java.security.Key;
import java.security.KeyPair;

/**
 * @description: 非对称算法,模长
 * @author: zhangzhenwei
 * @date: 2022/1/25 22:57
 */
public enum KeyAlgEnum {
  /**
   * asymmetrical key
   */
  SM2_256("EC",256),
  RSA_1024("RSA",1024),
  RSA_2048("RSA",2048),



  /**
   * symmetrical key
   */
  AES_128("AES",128,false),
  AES_256("AES",256,false),
  SM4_128("SM4",128,false),

  ;


  private String alg;
  private int keyLen;
  private Class keyType;
  private boolean isAsymm;


  <T>KeyAlgEnum(String alg, int keyLen,  boolean isAsymm) {
    this.alg = alg;
    this.keyLen = keyLen;
    this.isAsymm = isAsymm;
  }

  KeyAlgEnum(String alg, int keyLen) {
    this.alg = alg;
    this.keyLen = keyLen;
    this.isAsymm = true;
  }

  public boolean isAsymm() {
    return isAsymm;
  }

  public String getAlg() {
    return alg;
  }

  public int getKeyLen() {
    return keyLen;
  }

  public <T> Class<T> getKeyType() {
    return isAsymm? (Class<T>) KeyPair.class : (Class<T>) Key.class;
  }
}