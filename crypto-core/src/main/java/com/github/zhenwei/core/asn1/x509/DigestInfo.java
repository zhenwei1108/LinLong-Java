package com.github.zhenwei.core.asn1.x509;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;
import java.util.Enumeration;

/**
 * The DigestInfo object.
 * <pre>
 * DigestInfo::=SEQUENCE{
 *          digestAlgorithm  AlgorithmIdentifier,
 *          digest OCTET STRING }
 * </pre>
 */
public class DigestInfo
    extends ASN1Object {

  private byte[] digest;
  private AlgorithmIdentifier algId;

  public static DigestInfo getInstance(
      ASN1TaggedObject obj,
      boolean explicit) {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static DigestInfo getInstance(
      Object obj) {
    if (obj instanceof DigestInfo) {
      return (DigestInfo) obj;
    } else if (obj != null) {
      return new DigestInfo(ASN1Sequence.getInstance(obj));
    }

    return null;
  }

  public DigestInfo(
      AlgorithmIdentifier algId,
      byte[] digest) {
    this.digest = Arrays.clone(digest);
    this.algId = algId;
  }

  public DigestInfo(
      ASN1Sequence obj) {
    Enumeration e = obj.getObjects();

    algId = AlgorithmIdentifier.getInstance(e.nextElement());
    digest = ASN1OctetString.getInstance(e.nextElement()).getOctets();
  }

  public AlgorithmIdentifier getAlgorithmId() {
    return algId;
  }

  public byte[] getDigest() {
    return Arrays.clone(digest);
  }

  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(2);

    v.add(algId);
    v.add(new DEROctetString(digest));

    return new DERSequence(v);
  }
}