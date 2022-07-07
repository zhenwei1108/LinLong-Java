package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class PKCS7TypedStream
    extends CMSTypedStream {

  private final ASN1Encodable content;

  public PKCS7TypedStream(ASN1ObjectIdentifier oid, ASN1Encodable encodable)
      throws IOException {
    super(oid);

    content = encodable;
  }

  public ASN1Encodable getContent() {
    return content;
  }

  public InputStream getContentStream() {
    try {
      return getContentStream(content);
    } catch (IOException e) {
      throw new CMSRuntimeException("unable to convert content to stream: " + e.getMessage(), e);
    }
  }

  public void drain()
      throws IOException {
    content.toASN1Primitive(); // this will parse in the data
  }

  private InputStream getContentStream(ASN1Encodable encodable)
      throws IOException {
    byte[] encoded = encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    int index = 0;
    // Skip tag
    if ((encoded[index++] & 0x1F) == 0x1F) {
      while ((encoded[index++] & 0x80) != 0) {
      }
    }
    // Skip definite-length
    int dl = encoded[index++];
    if ((dl & 0x80) != 0) {
      index += (dl & 0x7F);
    }

    return new ByteArrayInputStream(encoded, index, encoded.length - index);
  }
}