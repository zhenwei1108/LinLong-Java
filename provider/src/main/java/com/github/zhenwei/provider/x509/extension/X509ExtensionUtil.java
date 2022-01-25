package com.github.zhenwei.provider.x509.extension;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1String;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.Extension;
import com.github.zhenwei.core.asn1.x509.GeneralName;
import com.github.zhenwei.core.util.Integers;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;


/**
 * @deprecated use com.github.zhenwei.pkix.cert.jcajce.JcaX509ExtensionUtils
 */
public class X509ExtensionUtil {

  /**
   * @deprecated use com.github.zhenwei.pkix.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue()
   */
  public static ASN1Primitive fromExtensionValue(
      byte[] encodedValue)
      throws IOException {
    ASN1OctetString octs = (ASN1OctetString) ASN1Primitive.fromByteArray(encodedValue);

    return ASN1Primitive.fromByteArray(octs.getOctets());
  }

  /**
   * @deprecated use com.github.zhenwei.pkix.cert.jcajce.JcaX509ExtensionUtils.getIssuerAlternativeNames()
   */
  public static Collection getIssuerAlternativeNames(X509Certificate cert)
      throws CertificateParsingException {
    byte[] extVal = cert.getExtensionValue(Extension.issuerAlternativeName.getId());

    return getAlternativeNames(extVal);
  }

  /**
   * @deprecated use com.github.zhenwei.pkix.cert.jcajce.JcaX509ExtensionUtils.getSubjectAlternativeNames()
   */
  public static Collection getSubjectAlternativeNames(X509Certificate cert)
      throws CertificateParsingException {
    byte[] extVal = cert.getExtensionValue(Extension.subjectAlternativeName.getId());

    return getAlternativeNames(extVal);
  }

  private static Collection getAlternativeNames(byte[] extVal)
      throws CertificateParsingException {
    if (extVal == null) {
      return Collections.EMPTY_LIST;
    }
    try {
      Collection temp = new ArrayList();
      Enumeration it = DERSequence.getInstance(fromExtensionValue(extVal)).getObjects();
      while (it.hasMoreElements()) {
        GeneralName genName = GeneralName.getInstance(it.nextElement());
        List list = new ArrayList();
        list.add(Integers.valueOf(genName.getTagNo()));
        switch (genName.getTagNo()) {
          case GeneralName.ediPartyName:
          case GeneralName.x400Address:
          case GeneralName.otherName:
            list.add(genName.getName().toASN1Primitive());
            break;
          case GeneralName.directoryName:
            list.add(X500Name.getInstance(genName.getName()).toString());
            break;
          case GeneralName.dNSName:
          case GeneralName.rfc822Name:
          case GeneralName.uniformResourceIdentifier:
            list.add(((ASN1String) genName.getName()).getString());
            break;
          case GeneralName.registeredID:
            list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
            break;
          case GeneralName.iPAddress:
            list.add(DEROctetString.getInstance(genName.getName()).getOctets());
            break;
          default:
            throw new IOException("Bad tag number: " + genName.getTagNo());
        }

        temp.add(list);
      }
      return Collections.unmodifiableCollection(temp);
    } catch (Exception e) {
      throw new CertificateParsingException(e.getMessage());
    }
  }
}