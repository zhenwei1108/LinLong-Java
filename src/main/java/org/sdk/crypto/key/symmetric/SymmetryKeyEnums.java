package org.sdk.crypto.key.symmetric;

public enum SymmetryKeyEnums {

  SM4_128("SM4",128),
  AES_128("AES",128),
  AES_192("AES",192),
  AES_256("AES",256),
  DES_64("DES",64),
  /**
   * 3DES
   */
  DESEDE_128("DESede",128),
  DESEDE_192("DESede",192),

  ;
  private String alg;
  private int length;

  SymmetryKeyEnums(String alg, int length) {
    this.alg = alg;
    this.length = length;
  }

  public String getAlg() {
    return alg;
  }

  public int getLength() {
    return length;
  }
}
