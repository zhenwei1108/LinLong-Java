package org.sdk.crypto.enums;

/**
 * @description: 对称密码算法
 * @author zhangzhenwei
 * @date 2021/1/13 9:51 上午
 */
public enum SymmetryKeyEnum {
  SM4(128),
  //分组长度64
  DES(56),
  DESede(128),//等同 3DES
  //AES分组长度 128
  AES128(128),
  AES192(192),
  AES256(256)
  ;


  private int keyLength;

  SymmetryKeyEnum(int keyLength) {
    this.keyLength = keyLength;
  }


  /**
   * @description: 获取对应算法模长
   * @param: []
   * @return: int
   * @author zhangzhenwei
   * @date: 2021/1/13 10:06 上午
   */
  public int getKeyLength() {
    return keyLength;
  }
}
