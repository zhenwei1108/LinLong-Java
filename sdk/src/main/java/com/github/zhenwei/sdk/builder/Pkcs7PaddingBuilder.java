package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.util.Arrays;

/**
 * @description: 进行PKCS7 填充.
 * 默认分组长度 16
 * @author: zhangzhenwei
 * @date: 2022/2/3 20:04
 */
public class Pkcs7PaddingBuilder {

  private static int DEFAULT_BLOCKING_SIZE = 16;

  public static byte[] encodePkcs7Padding(byte[] data) {
    byte[] padding = getPaddingLen(data);
    return Arrays.concatenate(data, padding);
  }


  public static byte[] decodePkcs7Padding(byte[] data) {
    int padLen = data[data.length - 1];
    byte[] result = new byte[data.length - padLen];
    System.arraycopy(data, 0, result, 0, result.length);
    return result;
  }


  private static byte[] getPaddingLen(byte[] data) {
    //原数据小于分组长度
    int resultLen;
    if (data.length < DEFAULT_BLOCKING_SIZE) {
      resultLen = DEFAULT_BLOCKING_SIZE - data.length;
    } else if ((resultLen = data.length % DEFAULT_BLOCKING_SIZE) == 0) {
      resultLen = DEFAULT_BLOCKING_SIZE;
    } else {
      resultLen = DEFAULT_BLOCKING_SIZE - resultLen;
    }
    byte[] padding = new byte[resultLen];
    java.util.Arrays.fill(padding, (byte) resultLen);
    return padding;
  }

  public void updateBlockingLen(int len){
    DEFAULT_BLOCKING_SIZE = len;
  }



}