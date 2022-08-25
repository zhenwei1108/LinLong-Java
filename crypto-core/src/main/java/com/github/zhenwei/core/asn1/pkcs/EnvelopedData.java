package com.github.zhenwei.core.asn1.pkcs;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.BERSequence;
import java.util.Enumeration;

/**
 * @description: EnvelopedData
 *  one pkcs7 content type ,can read rfc-2315
 *  EnvelopedData ::= SEQUENCE {
 *      version Version,
 *      recipientInfos RecipientInfos,
 *      encryptedContentInfo EncryptedContentInfo }
 *
 *    RecipientInfos ::= SET OF RecipientInfo
 *
 *
 *    RecipientInfo ::= SEQUENCE {
 *      version Version,
 *      issuerAndSerialNumber IssuerAndSerialNumber,
 *      keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *      encryptedKey EncryptedKey }
 *
 *    EncryptedKey ::= OCTET STRING
 *
 *    EncryptedContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *      encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 *    EncryptedContent ::= OCTET STRING
 * @author: zhangzhenwei
 * @since: 1.0
 * @date: 2022/8/24  23:11
 */
public class EnvelopedData extends ASN1Object {

  private ASN1Integer version;
  //RecipientInfo s
  private ASN1Set recipientInfos;

  private EncryptedContentInfo encryptedContentInfo;

  public static EnvelopedData getInstance(Object obj) {
    if (obj instanceof EnvelopedData) {
      return (EnvelopedData) obj;
    } else if (obj != null) {
      return new EnvelopedData(ASN1Sequence.getInstance(obj));
    }
    return null;
  }

  public EnvelopedData(ASN1Integer version, ASN1Set recipientInfos,
      EncryptedContentInfo encryptedContentInfo) {
    this.version = version;
    this.recipientInfos = recipientInfos;
    this.encryptedContentInfo = encryptedContentInfo;
  }

  private EnvelopedData(ASN1Sequence data) {
    Enumeration enumeration = data.getObjects();
    version = ASN1Integer.getInstance(enumeration.nextElement());
    recipientInfos = ASN1Set.getInstance(enumeration.nextElement());
    encryptedContentInfo = EncryptedContentInfo.getInstance(enumeration.nextElement());
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector(3);
    v.add(version);
    v.add(recipientInfos);
    v.add(encryptedContentInfo);
    return new BERSequence(v);
  }

  public ASN1Integer getVersion() {
    return version;
  }

  public ASN1Set getRecipientInfos() {
    return recipientInfos;
  }

  public EncryptedContentInfo getEncryptedContentInfo() {
    return encryptedContentInfo;
  }

}
