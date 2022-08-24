package com.github.zhenwei.core.asn1.pkcs;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.BERSequence;
import com.github.zhenwei.core.asn1.BERTaggedObject;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

/**
 * @description: EncryptedContentInfo
 *  EncryptedContentInfo ::= SEQUENCE {
 *        contentType ContentType,
 *        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 *      EncryptedContent ::= OCTET STRING
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/8/24  23:25
 */
public class EncryptedContentInfo extends ASN1Object {

  private ASN1ObjectIdentifier contentType;
  private AlgorithmIdentifier contentEncryptionAlgorithm;
  private ASN1OctetString encryptedContent;

  public EncryptedContentInfo(
      ASN1ObjectIdentifier contentType,
      AlgorithmIdentifier contentEncryptionAlgorithm,
      ASN1OctetString encryptedContent) {
    this.contentType = contentType;
    this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    this.encryptedContent = encryptedContent;
  }

  private EncryptedContentInfo(
      ASN1Sequence seq) {
    if (seq.size() < 2) {
      throw new IllegalArgumentException("Truncated Sequence Found");
    }

    contentType = (ASN1ObjectIdentifier) seq.getObjectAt(0);
    contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(
        seq.getObjectAt(1));
    if (seq.size() > 2) {
      encryptedContent = ASN1OctetString.getInstance(
          (ASN1TaggedObject) seq.getObjectAt(2), false);
    }
  }

  /**
   * Return an EncryptedContentInfo object from the given object.
   * <p>
   * Accepted inputs:
   * <ul>
   * <li> null &rarr; null
   * <li> {@link EncryptedContentInfo} object
   * <li> {@link com.github.zhenwei.core.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats
   * </ul>
   *
   * @param obj the object we want converted.
   * @throws IllegalArgumentException if the object cannot be converted.
   */
  public static EncryptedContentInfo getInstance(
      Object obj) {
    if (obj instanceof EncryptedContentInfo) {
      return (EncryptedContentInfo) obj;
    }
    if (obj != null) {
      return new EncryptedContentInfo(ASN1Sequence.getInstance(obj));
    }

    return null;
  }

  public ASN1ObjectIdentifier getContentType() {
    return contentType;
  }

  public AlgorithmIdentifier getContentEncryptionAlgorithm() {
    return contentEncryptionAlgorithm;
  }

  public ASN1OctetString getEncryptedContent() {
    return encryptedContent;
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   */
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);

    v.add(contentType);
    v.add(contentEncryptionAlgorithm);

    if (encryptedContent != null) {
      v.add(new BERTaggedObject(false, 0, encryptedContent));
    }

    return new BERSequence(v);
  }
}
