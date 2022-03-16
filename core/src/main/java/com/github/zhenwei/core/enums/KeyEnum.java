package com.github.zhenwei.core.enums;

public enum KeyEnum implements BaseKeyEnum{

  /**
   * symmetrical key
   */
  AES_128("AES",128),
  AES_256("AES",256),
  SM4_128("SM4",128),


  ;
  private String alg;
  private int keyLen;

  KeyEnum(String alg, int keyLen) {
    this.alg = alg;
    this.keyLen = keyLen;
  }

  @Override
  public String getAlg() {
    return alg;
  }

  @Override
  public int getKeyLen() {
    return keyLen;
  }
}