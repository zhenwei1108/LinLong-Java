package com.github.zhenwei.sdk.builder;

import java.security.SecureRandom;

/**
 * @description: 随机数
 * @author: zhangzhenwei
 * @since 1.0.0
 * @date: 2022/2/16 22:08
 */
public class RandomBuilder {

  public static byte[] genRandom(int len) {
    byte[] result = new byte[len];
    SecureRandom random = new SecureRandom();
    random.nextBytes(result);
    return result;
  }

}