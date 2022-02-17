package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @description: 证书构造
 * @author: zhangzhenwei
 * @date: 2022/2/16 22:46
 * @since 1.0.0
 */
public class CertBuilder {

  private X509Certificate cert;

  CertBuilder(X509Certificate cert) {
    this.cert = cert;
  }

  public static CertBuilder getInstance(Object obj) throws WeGooCryptoException {
    Certificate cert;
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509", new WeGooProvider());
      if (obj instanceof Certificate) {
        cert = (Certificate) obj;
      } else if (obj instanceof InputStream) {
        cert = factory.generateCertificate((InputStream) obj);
      } else if (obj instanceof byte[]) {
        cert = factory.generateCertificate(new ASN1InputStream((byte[]) obj));
      } else {
        throw new WeGooCryptoException(CryptoExceptionMassageEnum.params_err);
      }
      return new CertBuilder((X509Certificate) cert);
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.build_err, e);
    }
  }

  public X509Certificate getCert() {
    return this.cert;
  }

  public String getCertSn() {
    BigInteger serialNumber = this.cert.getSerialNumber();
    return Hex.toHexString(serialNumber.toByteArray());
  }

  public Date getNotBefore(){
    return this.cert.getNotBefore();
  }

  public Date getNotAfter(){
    return this.cert.getNotAfter();
  }

  public String getIssuerDN(){
    return this.cert.getIssuerDN().getName();
  }


  public String getSubjectDN(){
    return this.cert.getSubjectDN().getName();
  }

  public PublicKey getPublicKey(){
    return this.cert.getPublicKey();
  }

  public String getSigAlgName(){
    return this.cert.getSigAlgName();
  }


}