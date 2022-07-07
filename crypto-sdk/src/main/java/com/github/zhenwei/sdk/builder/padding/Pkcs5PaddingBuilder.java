package com.github.zhenwei.sdk.builder.padding;

/**
 * @description: 类似Pkcs7Padding
 * @author: zhangzhenwei
 * @date: 2022/2/6 21:44
 */
public class Pkcs5PaddingBuilder extends AbstractPkcs5Padding{

  private static int DEFAULT_BLOCKING_SIZE = 8;

  public static byte[] encodePadding(byte[] data) {
    return encoding(data,DEFAULT_BLOCKING_SIZE);
  }


}