package com.github.zhenwei.core.crypto.fpe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: zhangzhenwei
 * @description: UpperCaseStringType
 *  大写字母
 * @date: 2022/9/14  16:00
 * @since: 1.0.0
 */
public class UpperCaseStringType implements FpeType {

  char[] data = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

  final ConcurrentHashMap<Character, Byte> charToByte = new ConcurrentHashMap<>(
      (int) (data.length * 1.25) + 1);
  final ConcurrentHashMap<Byte, Character> byteToChar = new ConcurrentHashMap<>(charToByte.size());

  public UpperCaseStringType() {
    init();
  }

  @Override
  public char[] available() {
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
