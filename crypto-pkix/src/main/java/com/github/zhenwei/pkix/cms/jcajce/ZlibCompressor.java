package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.OutputCompressor;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;

public class ZlibCompressor
    implements OutputCompressor {

  private static final String ZLIB = "1.2.840.113549.1.9.16.3.8";

  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return new AlgorithmIdentifier(new ASN1ObjectIdentifier(ZLIB));
  }

  public OutputStream getOutputStream(OutputStream comOut) {
    return new DeflaterOutputStream(comOut);
  }
}