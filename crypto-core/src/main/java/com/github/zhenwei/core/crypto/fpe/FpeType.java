package com.github.zhenwei.core.crypto.fpe;

import com.github.zhenwei.core.crypto.params.FPEParameters;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import java.util.Map;

/**
 * @author: zhangzhenwei
 * @description: FpeType
 *  保留格式加密
 * @date: 2022/10/8  22:30
 * @since: 1.0
 */
public interface FpeType {

  /**
   * @author zhangzhenwei
   * @description 获取字典长度
   * @date 2022/10/8  22:30
   * @since: 1.0
   */
  default int radix() {
    return available().length;
  }

  /**
   * @author zhangzhenwei
   * @description 获取所有字典
   * @date 2022/10/8  22:30
   * @since: 1.0
   */
  Character[] available();

  /**
   * @author zhangzhenwei
   * @description 加密前转换，将字符转换为byte
   * @date 2022/10/8  22:29
   * @since: 1.0
   */
  default byte[] transform(char[] chars) {
    byte[] result = new byte[chars.length];
    for (int i = 0; i < chars.length; i++) {
      result[i] = getCharToByte().get(chars[i]);
    }
    return result;
  }

  /**
   * @author zhangzhenwei
   * @description 加密后转换，将byte 还原为char
   * @date 2022/10/8  22:29
   * @since: 1.0
   */
  default char[] transform(byte[] data) {
    char[] chars = new char[data.length];
    for (int i = 0; i < data.length; i++) {
      chars[i] = getByteToChar().get(data[i]);
    }
    return chars;
  }

  Map<Character, Byte> getCharToByte();

  Map<Byte, Character> getByteToChar();

  default void init() {
    Character[] available = available();
    for (Byte i = 0; i < available.length; i++) {
      getCharToByte().put(available[i], i);
      getByteToChar().put(i, available[i]);
    }
  }

  default byte[] cipher(FPEEngine fpeEngine, byte[] key, int radix, byte[] tweak, byte[] in,
      boolean doEncrypt) {
    fpeEngine.init(doEncrypt, new FPEParameters(new KeyParameter(key), radix, tweak));
    byte[] enc = new byte[in.length];
    fpeEngine.processBlock(in, 0, in.length, enc, 0);
    return enc;
  }

}
