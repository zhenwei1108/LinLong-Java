package com.github.zhenwei.sdk.enums;

import com.github.zhenwei.sdk.exception.WeGooDigestException;
import java.util.Arrays;

/**
 * @description: 摘要算法 枚举
 * @author: zhangzhenwei
 * @date: 2022/2/9 22:35
 */
public enum DigestAlgEnum implements BaseEnum {
  SM3(32),
  MD5(16),
  SHA1(20),
  SHA224(28),
  SHA256(32),
  SHA384(48),
  SHA512(64);

  private int digestLength;

  DigestAlgEnum(int digestLength) {
    this.digestLength = digestLength;
  }

  public int getDigestLength() {
    return digestLength;
  }

  public static DigestAlgEnum match(String name) throws WeGooDigestException {
    return Arrays.stream(values()).filter(digest -> digest.name().equalsIgnoreCase(name)).findFirst()
        .orElseThrow(() -> new WeGooDigestException("not match digest alg of: " + name));

  }


}