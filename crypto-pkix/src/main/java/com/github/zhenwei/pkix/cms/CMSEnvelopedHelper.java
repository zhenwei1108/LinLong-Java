package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.operator.DigestCalculator;
import com.github.zhenwei.pkix.util.asn1.cms.KEKRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cms.KeyAgreeRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cms.KeyTransRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cms.PasswordRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cms.RecipientInfo;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

class CMSEnvelopedHelper {

  static RecipientInformationStore buildRecipientInformationStore(
      ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm,
      CMSSecureReadable secureReadable) {
    return buildRecipientInformationStore(recipientInfos, messageAlgorithm, secureReadable, null);
  }

  static RecipientInformationStore buildRecipientInformationStore(
      ASN1Set recipientInfos, AlgorithmIdentifier messageAlgorithm,
      CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) {
    List infos = new ArrayList();
    for (int i = 0; i != recipientInfos.size(); i++) {
      RecipientInfo info = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));

      readRecipientInfo(infos, info, messageAlgorithm, secureReadable, additionalData);
    }
    return new RecipientInformationStore(infos);
  }

  private static void readRecipientInfo(
      List infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm,
      CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) {
    ASN1Encodable recipInfo = info.getInfo();
    if (recipInfo instanceof KeyTransRecipientInfo) {
      infos.add(new KeyTransRecipientInformation(
          (KeyTransRecipientInfo) recipInfo, messageAlgorithm, secureReadable, additionalData));
    } else if (recipInfo instanceof KEKRecipientInfo) {
      infos.add(new KEKRecipientInformation(
          (KEKRecipientInfo) recipInfo, messageAlgorithm, secureReadable, additionalData));
    } else if (recipInfo instanceof KeyAgreeRecipientInfo) {
      KeyAgreeRecipientInformation.readRecipientInfo(infos,
          (KeyAgreeRecipientInfo) recipInfo, messageAlgorithm, secureReadable, additionalData);
    } else if (recipInfo instanceof PasswordRecipientInfo) {
      infos.add(new PasswordRecipientInformation(
          (PasswordRecipientInfo) recipInfo, messageAlgorithm, secureReadable, additionalData));
    }
  }

  static class CMSDigestAuthenticatedSecureReadable
      implements CMSSecureReadable {

    private DigestCalculator digestCalculator;
    private final ASN1ObjectIdentifier contentType;
    private CMSReadable readable;

    public CMSDigestAuthenticatedSecureReadable(DigestCalculator digestCalculator,
        ASN1ObjectIdentifier contentType, CMSReadable readable) {
      this.digestCalculator = digestCalculator;
      this.contentType = contentType;
      this.readable = readable;
    }

    public ASN1ObjectIdentifier getContentType() {
      return contentType;
    }

    public InputStream getInputStream()
        throws IOException, CMSException {
      return new FilterInputStream(readable.getInputStream()) {
        public int read()
            throws IOException {
          int b = in.read();

          if (b >= 0) {
            digestCalculator.getOutputStream().write(b);
          }

          return b;
        }

        public int read(byte[] inBuf, int inOff, int inLen)
            throws IOException {
          int n = in.read(inBuf, inOff, inLen);

          if (n >= 0) {
            digestCalculator.getOutputStream().write(inBuf, inOff, n);
          }

          return n;
        }
      };
    }

    public byte[] getDigest() {
      return digestCalculator.getDigest();
    }
  }

  static class CMSAuthenticatedSecureReadable implements CMSSecureReadable {

    private AlgorithmIdentifier algorithm;
    private final ASN1ObjectIdentifier contentType;
    private CMSReadable readable;

    CMSAuthenticatedSecureReadable(AlgorithmIdentifier algorithm, ASN1ObjectIdentifier contentType,
        CMSReadable readable) {
      this.algorithm = algorithm;
      this.contentType = contentType;
      this.readable = readable;
    }

    public ASN1ObjectIdentifier getContentType() {
      return contentType;
    }

    public InputStream getInputStream()
        throws IOException, CMSException {
      return readable.getInputStream();
    }

  }

  static class CMSEnvelopedSecureReadable implements CMSSecureReadable {

    private AlgorithmIdentifier algorithm;
    private final ASN1ObjectIdentifier contentType;
    private CMSReadable readable;

    CMSEnvelopedSecureReadable(AlgorithmIdentifier algorithm, ASN1ObjectIdentifier contentType,
        CMSReadable readable) {
      this.algorithm = algorithm;
      this.contentType = contentType;
      this.readable = readable;
    }

    public ASN1ObjectIdentifier getContentType() {
      return contentType;
    }

    public InputStream getInputStream()
        throws IOException, CMSException {
      return readable.getInputStream();
    }

  }
}