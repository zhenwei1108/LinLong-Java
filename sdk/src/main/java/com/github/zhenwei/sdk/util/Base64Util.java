package com.github.zhenwei.sdk.util;

import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Base64;

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
//  public static boolean isBase64(String data) {
//    return Base64.isBase64(data);
//  }
  /**
   * @param [data]
   * @return boolean
   * @author zhangzhenwei
   * @description
   * Base64 包含 大小写字母, 数字, 反斜杠, 加号.  使用 等号 进行补位. 长度为 4的倍数
   *      a~z = 97~122
   *      A~Z = 65~90
   *      '=' = 61
   *      0~9 = 48~57
   *      / = 47
   *      + = 43
   * @date 2022/1/28 09:14
   */
  public static boolean isBase64(String data) {
    //长度为4的倍数
    if (data.length() % 4 != 0) {
      return false;
    }
    byte[] bytes = data.getBytes(StandardCharsets.UTF_8);

    for (byte aByte : bytes) {
      if (!(aByte == 61 ||aByte == 43 || aByte == 47 || (aByte >= 48 && aByte <= 57) || (aByte >= 65
          && aByte <= 90) || (aByte >= 97 && aByte <= 122))) {
        return false;
      }
    }
    return true;
  }
}