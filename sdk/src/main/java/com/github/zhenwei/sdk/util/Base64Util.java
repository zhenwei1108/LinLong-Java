package com.github.zhenwei.sdk.util;

import com.github.zhenwei.core.util.encoders.Base64;

public class Base64Util {

  /**
   * @param [data]
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 解码
   * @date 2022/1/28 13:55
   */
  public static String encode(byte[] data) {
    return Base64.toBase64String(data);
  }

  /**
   * @param [data]
   * @return byte[]
   * @author zhangzhenwei
   * @description 编码
   * @date 2022/1/28 13:55
   */
  public static byte[] decode(String data) {
    return Base64.decode(data);
  }

  /**
   * @param [data]
   * @return boolean
   * @author zhangzhenwei
   * @description 判断是否Base64
   * @date 2022/1/28 13:55
   */
  public static boolean isBase64(String data) {
    return Base64.isBase64(data);
  }

}