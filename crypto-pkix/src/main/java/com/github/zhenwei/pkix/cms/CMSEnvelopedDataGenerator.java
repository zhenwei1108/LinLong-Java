package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.asn1.BERSet;
import com.github.zhenwei.core.asn1.DERSet;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.OutputAEADEncryptor;
import com.github.zhenwei.pkix.operator.OutputEncryptor;
import com.github.zhenwei.pkix.util.asn1.cms.AttributeTable;
import com.github.zhenwei.pkix.util.asn1.cms.CMSObjectIdentifiers;
import com.github.zhenwei.pkix.util.asn1.cms.ContentInfo;
import com.github.zhenwei.pkix.util.asn1.cms.EncryptedContentInfo;
import com.github.zhenwei.pkix.util.asn1.cms.EnvelopedData;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Iterator;

/**
 * General class for generating a CMS enveloped-data message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
 *
 *       CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
 *
 *       edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *       CMSEnvelopedData ed = edGen.generate(
 *                                       msg,
 *                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *
 * </pre>
 */
public class CMSEnvelopedDataGenerator
    extends CMSEnvelopedGenerator {

  /**
   * base constructor
   */
  public CMSEnvelopedDataGenerator() {
  }

  private CMSEnvelopedData doGenerate(
      CMSTypedData content,
      OutputEncryptor contentEncryptor)
      throws CMSException {
    ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
    AlgorithmIdentifier encAlgId;
    ASN1OctetString encContent;

    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    try {
      OutputStream cOut = contentEncryptor.getOutputStream(bOut);

      content.write(cOut);

      cOut.close();

      if (contentEncryptor instanceof OutputAEADEncryptor) {
        byte[] mac = ((OutputAEADEncryptor) contentEncryptor).getMAC();

        bOut.write(mac, 0, mac.length);
      }
    } catch (IOException e) {
      throw new CMSException("");
    }

    byte[] encryptedContent = bOut.toByteArray();

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
    if (unprotectedAttributeGenerator != null) {
      AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(Collections.EMPTY_MAP);

      unprotectedAttrSet = new BERSet(attrTable.toASN1EncodableVector());
    }

    ContentInfo contentInfo = new ContentInfo(
        CMSObjectIdentifiers.envelopedData,
        new EnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, unprotectedAttrSet));

    return new CMSEnvelopedData(contentInfo);
  }

  /**
   * generate an enveloped object that contains an CMS Enveloped Data object using the given
   * provider.
   *
   * @param content          the content to be encrypted
   * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
   */
  public CMSEnvelopedData generate(
      CMSTypedData content,
      OutputEncryptor contentEncryptor)
      throws CMSException {
    return doGenerate(content, contentEncryptor);
  }
}