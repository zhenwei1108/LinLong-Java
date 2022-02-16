package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

public class CrlBuilder {

  CrlBuilder(X509CRL crl) {
    this.crl = crl;
  }

  private X509CRL crl;

  public static CrlBuilder getInstance(Object obj) throws WeGooCryptoException {
    X509CRL crl;
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509", new WeGooProvider());
      if (obj instanceof X509CRL) {
        crl = (X509CRL) obj;
      } else if (obj instanceof InputStream) {
        crl = (X509CRL) factory.generateCRL(new ASN1InputStream((InputStream) obj));
      } else if (obj instanceof byte[]) {
        crl = (X509CRL) factory.generateCRL(new ASN1InputStream((byte[]) obj));
      } else {
        throw new WeGooCryptoException(CryptoExceptionMassageEnum.params_err);
      }
      return new CrlBuilder(crl);
    } catch (WeGooCryptoException e) {
      throw e;
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.build_err, e);
    }
  }


  /**
   * @param [certBytes]
   * @return boolean
   * @author zhangzhenwei
   * @description 验证CRL
   * @date 2022/2/16 16:18
   * @since 1.0.8
   */
  public boolean verifyCrl(byte[] certBytes) {
    try {
      Certificate certificate = CertBuilder.getInstance(certBytes);
      crl.verify(certificate.getPublicKey());
      return true;
    } catch (Exception e) {
      return false;
    }
  }


  /**
   * @param [certSn]
   * @return java.util.Date
   * @author zhangzhenwei
   * @description 根据证书序列号, 获取注销时间
   * @date 2022/2/16 16:19
   * @since 1.0.8
   */
  public Date getRevokeTime(String certSn) {
    BigInteger bigInteger = new BigInteger(certSn, 16);
    X509CRLEntry entry = crl.getRevokedCertificate(bigInteger);
    return entry.getRevocationDate();
  }

  /**
   * @param [certSn]
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 根据证书序列号获取注销原因
   * @date 2022/2/16 16:20
   * @since 1.0.8
   */
  public String getRevokeReason(String certSn) throws WeGooCryptoException {
    try {
      BigInteger bigInteger = new BigInteger(certSn, 16);
      X509CRLEntry entry = crl.getRevokedCertificate(bigInteger);
      CRLReason revocationReason = entry.getRevocationReason();
      return revocationReason.name();
    } catch (Exception e) {
      throw new WeGooCryptoException(CryptoExceptionMassageEnum.parse_crl_err, e);
    }
  }

  /**
   * @param []
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 获取CRL颁发者DN
   * @date 2022/2/16 16:20
   * @since 1.0.8
   */
  public String getCrlIssue() {
    return crl.getIssuerDN().getName();
  }

  /**
   * @param []
   * @return java.util.Date
   * @author zhangzhenwei
   * @description 获取CRL下次更新时间
   * @date 2022/2/16 16:21
   * @since 1.0.8
   */
  public Date getCrlNextUpdateTime() {
    return crl.getNextUpdate();
  }

  /**
   * @param []
   * @return java.util.Date
   * @author zhangzhenwei
   * @description 获取CRL本次更新时间
   * @date 2022/2/16 16:21
   * @since 1.0.8
   */
  public Date getThisUpdateTime() {
    return crl.getThisUpdate();
  }

  /**
   * @param []
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 获取CRL签名算法
   * @date 2022/2/16 16:21
   * @since 1.0.8
   */
  public String getCrlSigAlgName() throws WeGooCryptoException {
    return SignAlgEnum.match(new ASN1ObjectIdentifier(crl.getSigAlgOID())).getAlg();
  }

  /**
   * @param []
   * @return java.util.Set<java.lang.String>
   * @author zhangzhenwei
   * @description 获取所有注销的证书序列号
   * @date 2022/2/16 16:24
   * @since 1.0.8
   */
  public List<String> getAllRevokedCertSn() {
    List<String> certSns = new ArrayList<String>();
    Set<? extends X509CRLEntry> entries = crl.getRevokedCertificates();
    for (X509CRLEntry entry : entries) {
      BigInteger serialNumber = entry.getSerialNumber();
      certSns.add(Hex.toHexString(serialNumber.toByteArray()));
    }
    return certSns;
  }


}