package com.github.zhenwei.core.crypto.fpe;

import java.util.HashMap;
import java.util.Map;

/**
 * @author: zhangzhenwei 
 * @description: LowCaseStringType
 *  小写字母
 * @date: 2022/9/14  15:51
 * @since: 1.0.0
 */
public class LowCaseStringType implements FpeType {

  final Character[] data = new Character[]{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
      'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};


  final HashMap<Character, Byte> charToByte = new HashMap<>(
      (int) (data.length * 1.25) + 1);
  final HashMap<Byte, Character> byteToChar = new HashMap<>(charToByte.size());

  public LowCaseStringType() {
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