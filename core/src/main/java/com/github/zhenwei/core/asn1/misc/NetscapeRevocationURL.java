package com.github.zhenwei.core.asn1.misc;

import com.github.zhenwei.core.asn1.ASN1IA5String;
import com.github.zhenwei.core.asn1.DERIA5String;

public class NetscapeRevocationURL
    extends DERIA5String {

  public NetscapeRevocationURL(
      ASN1IA5String str) {
    super(str.getString());
  }

  public String toString() {
    return "NetscapeRevocationURL: " + this.getString();
  }
}