package org.sdk.crypto.enums;

/**
 * @description: 非对称算法标识
 * @author: zhangzhenwei@bjca.org.cn
 * @date: 2021/4/25 5:45 下午
 */
public enum AsymmetryKeyEnum {
  RSA_1024("RSA",1024),
  RSA_2048("RSA",2048),
  SM2("EC",256),

  ;


  private String alg;

  private int length;

  AsymmetryKeyEnum(String alg, int length) {
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
