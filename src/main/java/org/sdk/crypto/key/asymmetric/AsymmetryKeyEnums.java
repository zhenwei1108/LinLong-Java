package org.sdk.crypto.key.asymmetric;

/**
 * @description: 非对称算法枚举  算法_模长
 * @author: zhangzhenwei@bjca.org.cn
 * @date: 2021/6/4 23:52
 */
public enum AsymmetryKeyEnums {
  RSA_1024("RSA", 1024),
  RSA_2048("RSA", 2048),
  RSA_4096("RSA", 4096),
  SM2_256("EC", 256),
  ED25519_256("ED25519", 256),

  ;

  private String algName;
  private int keyLength;

  AsymmetryKeyEnums(String algName, int keyLength) {
    this.algName = algName;
    this.keyLength = keyLength;
  }

  public String getAlgName() {
    return algName;
  }

  public int getKeyLength() {
    return keyLength;
  }
}
