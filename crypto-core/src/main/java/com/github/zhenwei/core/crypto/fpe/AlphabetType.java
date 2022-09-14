package com.github.zhenwei.core.crypto.fpe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


public class AlphabetType implements FpeType {

  char[] data = new char[]{

      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
      'T', 'U', 'V', 'W', 'X', 'Y', 'Z','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
      't', 'u', 'v', 'w', 'x', 'y', 'z'};

  final ConcurrentHashMap<Character, Byte> charToByte = new ConcurrentHashMap<>(
      (int) (data.length * 1.25) + 1);
  final ConcurrentHashMap<Byte, Character> byteToChar = new ConcurrentHashMap<>(charToByte.size());

  public AlphabetType() {
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
