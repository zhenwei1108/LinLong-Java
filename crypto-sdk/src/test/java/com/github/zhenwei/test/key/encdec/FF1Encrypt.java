package com.github.zhenwei.test.key.encdec;

import com.github.zhenwei.core.crypto.fpe.ChineseType;
import com.github.zhenwei.core.crypto.fpe.FPEEngine;
import com.github.zhenwei.core.crypto.fpe.FPEFF1Engine;
import com.github.zhenwei.core.crypto.fpe.FpeType;
import com.github.zhenwei.core.crypto.fpe.IntegerType;
import com.github.zhenwei.core.crypto.params.FPEParameters;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.util.encoders.Hex;
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
    FpeType integerType = new IntegerType();

    byte[] plainText = integerType.transform(data);
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

    byte[] plainText = fpeType.transform(data);
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



}
