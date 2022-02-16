package com.github.zhenwei.sdk.enums;

/**
 * @description: 签名算法
 * @author: zhangzhenwei
 * @date: 2022/2/3 20:57
 */
public enum SignAlgEnum implements BaseAlgEnum{
  SM3_WITH_SM2("SM3WithSM2"),
  SHA1_WITH_RSA("SHA1WithRSA"),
  SHA256_WITH_RSA("SHA256WithRSA"),

  ;

  private String alg;

  SignAlgEnum(String alg) {
    this.alg = alg;
  }

  public String getAlg() {
    return alg;
  }
}