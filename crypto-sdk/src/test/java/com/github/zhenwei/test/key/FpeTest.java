package com.github.zhenwei.test.key;

import com.github.zhenwei.core.enums.FpeAlgEnum;
import com.github.zhenwei.core.enums.FpeTypeEnum;
import com.github.zhenwei.core.enums.KeyEnum;
import com.github.zhenwei.sdk.builder.FpeBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import java.security.Key;
import org.junit.Test;

public class FpeTest {

  private static byte[] anyKey = new byte[]{
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
      (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x02,
      (byte) 0x03, (byte) 0x03, (byte) 0x03, (byte) 0x03
  };

  @Test
  public void mixDemo(){
    Key key = KeyBuilder.convertKey(anyKey, KeyEnum.AES_128);
    String data = "zhang，张振伟，123123123";
    String cipher = FpeBuilder.cipher(FpeAlgEnum.FPE_AES, FpeTypeEnum.FPE_TYPE_MIXING_CHAR, null,
        data, key, true);
    System.out.println(cipher);

  }



}
