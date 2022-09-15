package com.github.zhenwei.core.crypto.fpe;

import java.util.HashMap;
import java.util.Map;

/**
 * @author: zhangzhenwei
 * @description: UpperCaseStringType
 *  大写字母
 * @date: 2022/9/14  16:00
 * @since: 1.0.0
 */
public class UpperCaseStringType implements FpeType {

  Character[] data = new Character[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

  final HashMap<Character, Byte> charToByte = new HashMap<>(
      (int) (data.length * 1.25) + 1);
  final HashMap<Byte, Character> byteToChar = new HashMap<>(charToByte.size());

  public UpperCaseStringType() {
    init();
  }

  @Override
  public Character[] available() {
    return data;
  }

  @Override
  public Map<Character, Byte> getCharToByte() {
    return charToByte;
  }

  @Override
  public Map<Byte, Character> getByteToChar() {
    return byteToChar;
  }
}
