package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1String;
import com.github.zhenwei.core.asn1.DERUTF8String;

public class Hostname
    extends ASN1Object {

  private final String hostName;


  public Hostname(String hostName) {
    this.hostName = hostName;
  }

  public static Hostname getInstance(Object src) {
    if (src instanceof Hostname) {
      return (Hostname) src;
    }

    if (src instanceof String) {
      return new Hostname((String) src);
    }

    if (src instanceof ASN1String) {
      return new Hostname(((ASN1String) src).getString());
    }

    throw new IllegalArgumentException("hostname accepts Hostname, String and ASN1String");

  }

  public ASN1Primitive toASN1Primitive() {
    return new DERUTF8String(hostName);
  }
}