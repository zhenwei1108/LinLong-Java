package com.github.zhenwei.core.crypto.signers;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;
import java.io.IOException;
import java.math.BigInteger;


public class StandardDSAEncoding
    implements DSAEncoding {

  public static final org.bouncycastle.crypto.signers.StandardDSAEncoding INSTANCE = new org.bouncycastle.crypto.signers.StandardDSAEncoding();

  public byte[] encode(BigInteger n, BigInteger r, BigInteger s) throws IOException {
    ASN1EncodableVector v = new ASN1EncodableVector();
    encodeValue(n, v, r);
    encodeValue(n, v, s);
    return new DERSequence(v).getEncoded(ASN1Encoding.DER);
  }

  public BigInteger[] decode(BigInteger n, byte[] encoding) throws IOException {
    ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
    if (seq.size() == 2) {
      BigInteger r = decodeValue(n, seq, 0);
      BigInteger s = decodeValue(n, seq, 1);

      byte[] expectedEncoding = encode(n, r, s);
      if (Arrays.areEqual(expectedEncoding, encoding)) {
        return new BigInteger[]{r, s};
      }
    }

    throw new IllegalArgumentException("Malformed signature");
  }

  protected BigInteger checkValue(BigInteger n, BigInteger x) {
    if (x.signum() < 0 || (null != n && x.compareTo(n) >= 0)) {
      throw new IllegalArgumentException("Value out of range");
    }

    return x;
  }

  protected BigInteger decodeValue(BigInteger n, ASN1Sequence s, int pos) {
    return checkValue(n, ((ASN1Integer) s.getObjectAt(pos)).getValue());
  }

  protected void encodeValue(BigInteger n, ASN1EncodableVector v, BigInteger x) {
    v.add(new ASN1Integer(checkValue(n, x)));
  }
}