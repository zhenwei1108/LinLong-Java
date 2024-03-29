package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.DLSet;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.OutputAEADEncryptor;
import com.github.zhenwei.pkix.util.asn1.cms.AttributeTable;
import com.github.zhenwei.pkix.util.asn1.cms.AuthEnvelopedData;
import com.github.zhenwei.pkix.util.asn1.cms.CMSObjectIdentifiers;
import com.github.zhenwei.pkix.util.asn1.cms.ContentInfo;
import com.github.zhenwei.pkix.util.asn1.cms.EncryptedContentInfo;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Iterator;

public class CMSAuthEnvelopedDataGenerator
    extends CMSAuthEnvelopedGenerator {

  /**
   * base constructor
   */
  public CMSAuthEnvelopedDataGenerator() {
  }

  private CMSAuthEnvelopedData doGenerate(
      CMSTypedData content,
      OutputAEADEncryptor contentEncryptor)
      throws CMSException {
    ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
    AlgorithmIdentifier encAlgId;
    ASN1OctetString encContent;

    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    ASN1Set authenticatedAttrSet = null;
    try {
      OutputStream cOut = contentEncryptor.getOutputStream(bOut);

      content.write(cOut);

      if (authAttrsGenerator != null) {
        AttributeTable attrTable = authAttrsGenerator.getAttributes(Collections.EMPTY_MAP);

        authenticatedAttrSet = new DERSet(attrTable.toASN1EncodableVector());

        contentEncryptor.getAADStream().write(authenticatedAttrSet.getEncoded(ASN1Encoding.DER));
      }

      cOut.close();
    } catch (IOException e) {
      throw new CMSException("unable to process authenticated content: " + e.getMessage(), e);
    }

    byte[] encryptedContent = bOut.toByteArray();
    byte[] mac = contentEncryptor.getMAC();

    encAlgId = contentEncryptor.getAlgorithmIdentifier();

    encContent = new BEROctetString(encryptedContent);

    GenericKey encKey = contentEncryptor.getKey();

    for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext(); ) {
      RecipientInfoGenerator recipient = (RecipientInfoGenerator) it.next();

      recipientInfos.add(recipient.generate(encKey));
    }

    EncryptedContentInfo eci = new EncryptedContentInfo(
        content.getContentType(),
        encAlgId,
        encContent);

    ASN1Set unprotectedAttrSet = null;
    if (unauthAttrsGenerator != null) {
      AttributeTable attrTable = unauthAttrsGenerator.getAttributes(Collections.EMPTY_MAP);

      unprotectedAttrSet = new DLSet(attrTable.toASN1EncodableVector());
    }

    ContentInfo contentInfo = new ContentInfo(
        CMSObjectIdentifiers.authEnvelopedData,
        new AuthEnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, authenticatedAttrSet,
            new DEROctetString(mac), unprotectedAttrSet));

    return new CMSAuthEnvelopedData(contentInfo);
  }

  /**
   * generate an auth-enveloped object that contains an CMS Enveloped Data object using the given
   * provider.
   *
   * @param content          the content to be encrypted
   * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
   */
  public CMSAuthEnvelopedData generate(
      CMSTypedData content,
      OutputAEADEncryptor contentEncryptor)
      throws CMSException {
    return doGenerate(content, contentEncryptor);
  }
}