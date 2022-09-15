package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.engines.SM4Engine;
import com.github.zhenwei.core.crypto.fpe.FPEEngine;
import com.github.zhenwei.core.crypto.fpe.FPEFF1Engine;
import com.github.zhenwei.core.crypto.fpe.FpeType;
import com.github.zhenwei.core.crypto.params.FPEParameters;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.enums.FpeAlgEnum;
import com.github.zhenwei.core.enums.FpeTypeEnum;
import java.security.Key;

public class FpeBuilder {


  public void cipher(FpeAlgEnum fpeAlgEnum, FpeTypeEnum fpeTypeEnum, byte[] tweak, String data,
      Key key) {
    //aes,sm4
    FPEEngine fpeEngine =
        fpeAlgEnum == FpeAlgEnum.FPE_SM4 ? new FPEFF1Engine(new SM4Engine()) : new FPEFF1Engine();
    FpeType fpeType = fpeTypeEnum.getFpeType();
    char[] chars = data.toCharArray();
    byte[] plainText = fpeType.transform(chars);
    int radix = fpeType.radix();
    fpeEngine.init(true, new FPEParameters(new KeyParameter(key.getEncoded()), radix, tweak));
    byte[] enc = new byte[chars.length];
    fpeEngine.processBlock(plainText, 0, plainText.length, enc, 0);
    char[] cipherData = fpeType.transform(enc);
  }


}
