package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.crypto.Digest;
import com.github.zhenwei.core.crypto.digests.SHA1Digest;
import com.github.zhenwei.core.crypto.digests.SHA224Digest;
import com.github.zhenwei.core.crypto.digests.SHA256Digest;
import com.github.zhenwei.core.crypto.digests.SHA384Digest;
import com.github.zhenwei.core.crypto.digests.SHA512Digest;
import com.github.zhenwei.core.crypto.digests.SM3Digest;
import com.github.zhenwei.core.crypto.macs.HMac;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.exception.IExceptionEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.security.Key;

public class Mac {


  public byte[] hmac(DigestAlgEnum digestAlgEnum, Key key, byte[] source) {
    Digest digest;
    switch (digestAlgEnum) {
      case SHA1: digest = new SHA1Digest(); break;
      case SHA224: digest = new SHA224Digest(); break;
      case SHA256: digest = new SHA256Digest(); break;
      case SHA384: digest = new SHA384Digest(); break;
      case SHA512: digest = new SHA512Digest(); break;
      //default sm3 digest
      default: digest = new SM3Digest(); break;
    }
    HMac hMac = new HMac(digest);
    hMac.init(new KeyParameter(key.getEncoded()));
    hMac.update(source, 0, source.length);
    byte[] result = new byte[hMac.getMacSize()];
    hMac.doFinal(result, 0);
    return result;
  }

  public void cmac() throws WeGooCryptoException {
    throw new WeGooCryptoException(IExceptionEnum.not_support_now);
  }

}