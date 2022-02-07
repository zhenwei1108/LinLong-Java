package com.github.zhenwei.sdk.enums;

public enum CipherAlgEnum {


  ;

  private String alg;

  CipherAlgEnum(String alg) {
    this.alg = alg;
  }

  public String getAlg() {
    return alg;
  }
}