package com.github.zhenwei.pkix.util.asn1.cmp;

import com.github.zhenwei.core.asn1.ASN1BitString;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.util.asn1.crmf.CertId;

public class OOBCertHash
    extends ASN1Object {

  private AlgorithmIdentifier hashAlg;
  private CertId certId;
  private ASN1BitString hashVal;

  private OOBCertHash(ASN1Sequence seq) {
    int index = seq.size() - 1;

    hashVal = ASN1BitString.getInstance(seq.getObjectAt(index--));

    for (int i = index; i >= 0; i--) {
      ASN1TaggedObject tObj = (ASN1TaggedObject) seq.getObjectAt(i);

      if (tObj.getTagNo() == 0) {
        hashAlg = AlgorithmIdentifier.getInstance(tObj, true);
      } else {
        certId = CertId.getInstance(tObj, true);
      }
    }

  }

  public static OOBCertHash getInstance(Object o) {
    if (o instanceof OOBCertHash) {
      return (OOBCertHash) o;
    }

    if (o != null) {
      return new OOBCertHash(ASN1Sequence.getInstance(o));
    }

    return null;
  }

  public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal) {
    this(hashAlg, certId, new DERBitString(hashVal));
  }

  public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, DERBitString hashVal) {
    this.hashAlg = hashAlg;
    this.certId = certId;
    this.hashVal = hashVal;
  }

  public AlgorithmIdentifier getHashAlg() {
    return hashAlg;
  }

  public CertId getCertId() {
    return certId;
  }

  public ASN1BitString getHashVal() {
    return hashVal;
  }

  /**
   * <pre>
   * OOBCertHash ::= SEQUENCE {
   *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
   *                      certId      [1] CertId                  OPTIONAL,
   *                      hashVal         BIT STRING
   *                      -- hashVal is calculated over the DER encoding of the
   *                      -- self-signed certificate with the identifier certID.
   *       }
   * </pre>
   *
   * @return a basic ASN.1 object representation.
   */
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);

    addOptional(v, 0, hashAlg);
    addOptional(v, 1, certId);

    v.add(hashVal);

    return new DERSequence(v);
  }

  private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
    if (obj != null) {
      v.add(new DERTaggedObject(true, tagNo, obj));
    }
  }
}