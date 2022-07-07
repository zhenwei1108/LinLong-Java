package com.github.zhenwei.provider.jcajce.provider.util;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.ntt.NTTObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.util.Integers;
import java.util.HashMap;
import java.util.Map;

public class SecretKeyUtil {

  private static Map keySizes = new HashMap();

  static {
    keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(192));

    keySizes.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
    keySizes.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
    keySizes.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));

    keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
    keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
    keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));
  }

  public static int getKeySize(ASN1ObjectIdentifier oid) {
    Integer size = (Integer) keySizes.get(oid);

    if (size != null) {
      return size.intValue();
    }

    return -1;
  }
}