package com.github.zhenwei.sdk.util;

public class PaddingUtil {

  public static byte[] getPaddingLen(byte[] data, int blockingSize) {
    //原数据小于分组长度
    int resultLen;
    if (data.length < blockingSize) {
      resultLen = blockingSize - data.length;
    } else if ((resultLen = data.length % blockingSize) == 0) {
      resultLen = blockingSize;
    } else {
      resultLen = blockingSize - resultLen;
    }
    byte[] padding = new byte[resultLen];
    java.util.Arrays.fill(padding, (byte) resultLen);
    return padding;
  }

}