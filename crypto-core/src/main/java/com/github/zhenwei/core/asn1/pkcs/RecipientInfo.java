package com.github.zhenwei.core.asn1.pkcs;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

/**
 * @description: RecipientInfo
 *  RecipientInfo ::= SEQUENCE {
 *       version Version,
 *       issuerAndSerialNumber IssuerAndSerialNumber,
 *       keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *       encryptedKey EncryptedKey }
 *
 *       EncryptedKey ::= OCTET STRING
 *
 * @author: zhangzhenwei
 * @since: 1.0.0
 * @date: 2022/8/24  23:21
 */
public class RecipientInfo extends ASN1Object {

  private ASN1Integer version;

  private IssuerAndSerialNumber issuerAndSerialNumber;

  private AlgorithmIdentifier algorithmIdentifier;

  private ASN1OctetString encryptedKey;

  public static RecipientInfo getInstance(Object obj){
    if (obj instanceof RecipientInfo){
      return (RecipientInfo)obj;
    }else if (obj!= null){
      return new RecipientInfo(ASN1Sequence.getInstance(obj));
    }
    return null;
  }


  private RecipientInfo(ASN1Sequence sequence) {
    Enumeration enumeration = sequence.getObjects();
    version = ASN1Integer.getInstance(enumeration.nextElement());
    issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(enumeration.nextElement());
    algorithmIdentifier = AlgorithmIdentifier.getInstance(enumeration.nextElement());
    encryptedKey = ASN1OctetString.getInstance(enumeration.nextElement());
  }

  public RecipientInfo(ASN1Integer version,
      IssuerAndSerialNumber issuerAndSerialNumber,
      AlgorithmIdentifier algorithmIdentifier,
      ASN1OctetString encryptedKey) {
    this.version = version;
    this.issuerAndSerialNumber = issuerAndSerialNumber;
    this.algorithmIdentifier = algorithmIdentifier;
    this.encryptedKey = encryptedKey;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(4);
    v.add(version);
    v.add(issuerAndSerialNumber);
    v.add(algorithmIdentifier);
    v.add(encryptedKey);
    return new DERSequence(v);
  }
}
