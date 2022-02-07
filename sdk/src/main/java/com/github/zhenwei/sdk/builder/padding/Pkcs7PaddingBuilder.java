package com.github.zhenwei.sdk.builder.padding;

import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.sdk.util.PaddingUtil;
import lombok.var;

/**
 * @description: 进行PKCS7 填充. 类似 PKCS5Padding 默认分组长度 16
 * @author: zhangzhenwei
 * @date: 2022/2/3 20:04
 */
public class Pkcs7PaddingBuilder {

  private static int DEFAULT_BLOCKING_SIZE = 16;

  public static byte[] encodePkcs7Padding(byte[] data) {
    var padding = PaddingUtil.getPaddingLen(data, DEFAULT_BLOCKING_SIZE);
    return Arrays.concatenate(data, padding);
  }


  public static byte[] decodePkcs7Padding(byte[] data) {
    var padLen = data[data.length - 1];
    var result = new byte[data.length - padLen];
    System.arraycopy(data, 0, result, 0, result.length);
    return result;
  }


}