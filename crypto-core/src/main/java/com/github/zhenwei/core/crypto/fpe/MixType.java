package com.github.zhenwei.core.crypto.fpe;

import com.github.zhenwei.core.util.Pack;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author: zhangzhenwei
 * @description: MixType
 *  混合
 * @date: 2022/9/14  22:15
 * @since: 1.0.0
 */
public class MixType implements FpeType {

  Character[] data;
  LinkedHashMap<MixEntity, Map<Integer, Character>> map = new LinkedHashMap<>();
  LinkedHashMap<Integer, Character> other = new LinkedHashMap<>();
  ConcurrentHashMap<Character, Short> charToByte;
  ConcurrentHashMap<Short, Character> byteToChar;

  public MixType() {
    DigitType digitType = new DigitType();
    List<Character> integers = Arrays.asList(digitType.available());
    MixEntity integersEntity = new MixEntity(digitType, integers);
    map.put(integersEntity, new HashMap<>());
    AlphabetType alphabetType = new AlphabetType();
    List<Character> alphabets = Arrays.asList(alphabetType.available());
    MixEntity alphabetsEntity = new MixEntity(alphabetType, alphabets);
    map.put(alphabetsEntity, new HashMap<>());
    ChineseType chineseType = new ChineseType();
    List<Character> chineses = Arrays.asList(chineseType.available());
    MixEntity chinesesEntity = new MixEntity(chineseType, chineses);
    map.put(chinesesEntity, new HashMap<>());
//    MixEntity other = new MixEntity(null, null);
//    map.put(other, new HashMap<>());

    data = new Character[integers.size() + alphabets.size() + chineses.size()];
    int index = 0;
    System.arraycopy(integers.toArray(), 0, data, index, index += integers.size());
    System.arraycopy(alphabets.toArray(), 0, data, index, alphabets.size());
    index += alphabets.size();
    System.arraycopy(chineses.toArray(), 0, data, index, chineses.size());
    charToByte = new ConcurrentHashMap<>((int) (data.length * 1.25) + 1);
    byteToChar = new ConcurrentHashMap<>(charToByte.size());
    init();
  }

  @Override
  public Character[] available() {
    return data;
  }

  @Override
  public Map<Character, Byte> getCharToByte() {
    return null;
  }

  @Override
  public Map<Byte, Character> getByteToChar() {
    return null;
  }


  @Override
  public byte[] transform(char[] in) {
    for (int i = 0; i < in.length; i++) {
      List<Character> characters = Arrays.asList(available());
      int index = characters.indexOf(in[i]);
      //-1 不在范围内，或为标点符号。
      if (index > -1) {
        for (Entry<MixEntity, Map<Integer, Character>> entry : map.entrySet()) {
          MixEntity key = entry.getKey();
          if (key.getList().contains(in[i])) {
            entry.getValue().put(i, in[i]);
            break;
          }
        }
      } else {
        //捕获标点符号。
        other.put(i, in[i]);
      }
    }

    byte[] result = new byte[0];
    for (Entry<MixEntity, Map<Integer, Character>> entry : map.entrySet()) {
      MixEntity key = entry.getKey();
      Map<Integer, Character> value = entry.getValue();
      Collection<Character> values = value.values();
      Character[] characters = values.toArray(new Character[0]);
      char[] data = new char[characters.length];
      for (int i = 0; i < characters.length; i++) {
        data[i] = characters[i];
      }
      byte[] transform = key.getFpeType().transform(data);
      byte[] total = new byte[transform.length + result.length];
      System.arraycopy(result, 0, total, 0, result.length);
      System.arraycopy(transform, 0, total, result.length, transform.length);
      result = total;
    }
    return result;
  }

  @Override
  public char[] transform(byte[] data) {
    char[] chars = new char[data.length / 2];
    for (int i = 1; i <= data.length; i++) {
      //奇数
      if ((i & 1) != 0) {
        byte[] bytes = new byte[2];
        System.arraycopy(data, i - 1, bytes, 0, 2);
        short i1 = Pack.bigEndianToShort(bytes, 0);
        Character character = byteToChar.get(i1);
        chars[i / 2] = character;
      }

    }
    return chars;
  }

  @Override
  public void init() {
    Character[] available = available();
    for (short i = 0; i < available.length; i++) {
      charToByte.put(available[i], i);
      byteToChar.put(i, available[i]);
    }
  }

  public LinkedHashMap<MixEntity, Map<Integer, Character>> getMap() {
    return map;
  }

  public LinkedHashMap<Integer, Character> getOther() {
    return other;
  }
}
