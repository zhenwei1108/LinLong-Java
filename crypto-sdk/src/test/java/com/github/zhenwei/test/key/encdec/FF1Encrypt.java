package com.github.zhenwei.test.key.encdec;

import com.github.zhenwei.core.crypto.fpe.ChineseType;
import com.github.zhenwei.core.crypto.fpe.FPEEngine;
import com.github.zhenwei.core.crypto.fpe.FPEFF1Engine;
import com.github.zhenwei.core.crypto.fpe.FpeType;
import com.github.zhenwei.core.crypto.fpe.DigitType;
import com.github.zhenwei.core.crypto.fpe.MixEntity;
import com.github.zhenwei.core.crypto.fpe.MixType;
import com.github.zhenwei.core.crypto.params.FPEParameters;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.util.encoders.Hex;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import org.junit.Test;

public class FF1Encrypt {

  private static byte[] anyKey = new byte[]{
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
      (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x02,
      (byte) 0x03, (byte) 0x03, (byte) 0x03, (byte) 0x03
  };


  @Test
  public void testFF1wInteger() throws Exception {
    String data = "0123456789123";
    FpeType integerType = new DigitType();

    char[] chars = data.toCharArray();
    byte[] plainText = integerType.transform(chars);
    byte[] tweak = Hex.decode("");
    FPEEngine fpeEngine = new FPEFF1Engine();
    int radix = integerType.radix();
    fpeEngine.init(true, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

    byte[] enc = new byte[plainText.length];

    fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);
    //ecn = 24334 77484
    System.out.println("ff1w encrypt:" + integerType.transform(enc));
    System.out.println("ff1w encrypt:" + new String(enc));
    fpeEngine.init(false, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

    byte[] result = new byte[enc.length];
    fpeEngine.processBlock(enc, 0, enc.length, result, 0);
    System.out.println("ff1w decrypt :" + new String(result));

  }


  @Test
  public void testFF1wChinese() throws Exception {
    String data = "张振伟";
    FpeType fpeType = new ChineseType();

    byte[] plainText = fpeType.transform(data.toCharArray());
    System.out.println(Hex.toHexString(plainText));
    byte[] tweak = Hex.decode("");
    FPEEngine fpeEngine = new FPEFF1Engine();
    int radix = fpeType.radix();
    fpeEngine.init(true, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

    byte[] enc = new byte[plainText.length];

    fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);

    System.out.println("ff1w encrypt:" + fpeType.transform(enc));

    fpeEngine.init(false, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

    byte[] result = new byte[enc.length];
    fpeEngine.processBlock(enc, 0, enc.length, result, 0);
    System.out.println("ff1w decrypt:" + Hex.toHexString(result));
    System.out.println(fpeType.transform(result));

  }

  @Test
  public void testFF1wMix() throws Exception {
    String data = "zhang，张振伟，123123123";
    MixType fpeType = new MixType();

    char[] in = data.toCharArray();
    fpeType.transform(in);
    LinkedHashMap<MixEntity, Map<Integer, Character>> map = fpeType.getMap();
    LinkedHashMap<Integer, Character> other = fpeType.getOther();
    char[] cipher = new char[in.length];
    char[] decrypt = new char[in.length];
    for (Entry<MixEntity, Map<Integer, Character>> entry : map.entrySet()) {
      MixEntity key = entry.getKey();
      Map<Integer, Character> value = entry.getValue();
      Collection<Character> values = value.values();
      Character[] characters = values.toArray(new Character[0]);
      char[] result = new char[characters.length];
      for (int i = 0; i < characters.length; i++) {
        result[i] = characters[i];
      }
      byte[] plainText = key.getFpeType().transform(result);

      System.out.println(Hex.toHexString(plainText));
      byte[] tweak = Hex.decode("");
      FPEEngine fpeEngine = new FPEFF1Engine();
      int radix = key.getFpeType().radix();
      fpeEngine.init(true, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

      byte[] enc = new byte[plainText.length];

      fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);
      System.out.println("ff1w encrypt：" + new String(key.getFpeType().transform(enc)));

      char[] transform = key.getFpeType().transform(enc);

      fpeEngine.init(false, new FPEParameters(new KeyParameter(anyKey), radix, tweak));

      byte[] decData = new byte[enc.length];
      fpeEngine.processBlock(enc, 0, enc.length, decData, 0);
      char[] transform1 = key.getFpeType().transform(decData);

      int order = 0;
      for (Entry<Integer, Character> characterEntry : value.entrySet()) {
        Integer index = characterEntry.getKey();
        cipher[index] = transform[order];
        decrypt[index] = transform1[order++];
      }
      for (Entry<Integer, Character> characterEntry : other.entrySet()) {
        Integer index = characterEntry.getKey();
        Character value1 = characterEntry.getValue();
        cipher[index] = value1;
        decrypt[index] = value1;
      }

      System.out.println("ff1w decrypt：" + new String(transform1));

    }
    System.out.println("结果：" + new String(cipher));
    System.out.println("结果：" + new String(decrypt));

  }


}
