package com.github.zhenwei.sdk.builder.padding;

/**
 * @description: 进行PKCS7 填充. 类似 PKCS5Padding 默认分组长度 16
 * @author: zhangzhenwei
 * @date: 2022/2/3 20:04
 */
public class Pkcs7PaddingBuilder extends AbstractPkcs5Padding{

  private static int DEFAULT_BLOCKING_SIZE = 16;

  public static byte[] encoding(byte[] data) {
    return encoding(data, DEFAULT_BLOCKING_SIZE);
  }





}