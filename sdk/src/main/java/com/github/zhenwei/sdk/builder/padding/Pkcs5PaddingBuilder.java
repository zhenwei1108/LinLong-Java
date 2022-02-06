package com.github.zhenwei.sdk.builder.padding;

import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.sdk.util.PaddingUtil;

/**
 * @description: 类似Pkcs7Padding
 * @author: zhangzhenwei
 * @date: 2022/2/6 21:44
 */
public class Pkcs5PaddingBuilder extends Pkcs7PaddingBuilder{

  private static int DEFAULT_BLOCKING_SIZE = 8;

  public static byte[] encodePkcs5Padding(byte[] data) {
    byte[] padding = PaddingUtil.getPaddingLen(data, DEFAULT_BLOCKING_SIZE);
    return Arrays.concatenate(data, padding);
  }

  public static byte[] decodePkcs5Padding(byte[] data) {
    int padLen = data[data.length - 1];
    byte[] result = new byte[data.length - padLen];
    System.arraycopy(data, 0, result, 0, result.length);
    return result;
  }

}