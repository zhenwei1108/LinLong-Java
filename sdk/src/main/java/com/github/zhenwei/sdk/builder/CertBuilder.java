package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.*;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cert.X509v3CertificateBuilder;
import com.github.zhenwei.pkix.cert.bc.BcX509ExtensionUtils;
import com.github.zhenwei.pkix.operator.bc.BcContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcECContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcRSAContentSignerBuilder;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.provider.jce.spec.ECParameterSpec;
import com.github.zhenwei.sdk.util.BytesUtil;
import com.github.zhenwei.sdk.util.DateUtil;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.TimeUnit;

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
            } else if (obj instanceof ASN1Encodable) {
                cert = factory.generateCertificate(
                        new ASN1InputStream(((ASN1Encodable) obj).toASN1Primitive().getEncoded()));
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

    public com.github.zhenwei.core.asn1.x509.Certificate getCert0() throws WeGooCryptoException {
        try {
            return com.github.zhenwei.core.asn1.x509.Certificate.getInstance(this.cert.getEncoded());
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.build_err, e);
        }
    }




    public String getCertSn() {
        BigInteger serialNumber = this.cert.getSerialNumber();
        return Hex.toHexString(serialNumber.toByteArray());
    }


    /**
     * @param [dn, publicKey, privateKey]
     * @return java.security.cert.Certificate
     * @author zhangzhenwei
     * @description 生成证书
     * todo just support sm2
     * @date 2022/3/15  9:09 下午
     * @since: 1.0.0
     */
    public static byte[] generateCertificate(String subjectDn, String issuerDn, PublicKey publicKey,
                                             PrivateKey privateKey, SignAlgEnum signAlgEnum, int time, TimeUnit timeUnit) throws WeGooCryptoException {
        try {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
//            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo)publicKey;
            X500Name subject = new X500Name(subjectDn);
            X500Name issuer = new X500Name(issuerDn);
            byte[] bytes = new byte[15];
            Random random = new Random();
            random.nextBytes(bytes);
            byte[] bytes1 = BytesUtil.mergeBytes("9".getBytes(StandardCharsets.UTF_8), bytes);
            BigInteger sn = new BigInteger(bytes1);
            Date notBefore = DateUtil.now();
            int max = Math.max(1, (int) timeUnit.toDays(time));
            Date notAfter = DateUtil.nowPlusDays(max);
            BcX509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
            //密钥用途：  签名和不可抵赖
            int usage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation;
            //使用者标识符
            SubjectKeyIdentifier subjectKeyIdentifier = x509ExtensionUtils.createSubjectKeyIdentifier(publicKeyInfo);
//        授权者标识符
            AuthorityKeyIdentifier authorityKeyIdentifier = x509ExtensionUtils.createAuthorityKeyIdentifier(publicKeyInfo);

            //判断是否签发根证书
            if (subject.toString().equals(subject.toString())) {
                //根证书 颁发者标识符
                authorityKeyIdentifier = x509ExtensionUtils.createAuthorityKeyIdentifier(publicKeyInfo);
                //补充证书签名用途
                usage = usage | KeyUsage.keyCertSign;
            }
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, sn, notBefore, notAfter, subject, publicKeyInfo);

            //增加扩展项
            Extension keyUsage = new Extension(Extension.keyUsage, false, new KeyUsage(usage).getEncoded());
            Extension subjectKeyId = new Extension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier.getEncoded());
            Extension authorityKeyId = new Extension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier.getEncoded());
            AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(signAlgEnum.getOid());
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(signAlgEnum.getDigestAlgEnum().getOid());
            builder.addExtension(keyUsage);
            builder.addExtension(subjectKeyId);
            builder.addExtension(authorityKeyId);
            X509CertificateHolder holder;
            BcContentSignerBuilder signerBuilder;
            AsymmetricKeyParameter keyParameters;
            if (publicKey.getAlgorithm().equals("EC")) {
                signerBuilder = new BcECContentSignerBuilder(sigAlgId, digAlgId);
                BCECPrivateKey key = (BCECPrivateKey) privateKey;
                ECParameterSpec parameters = key.getParameters();
                ECDomainParameters params = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN());
                keyParameters = new ECPrivateKeyParameters(key.getD(), params);
                holder = builder.build(signerBuilder.build(keyParameters));
            } else {
                BCRSAPrivateKey key = (BCRSAPrivateKey) privateKey;
                signerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
                keyParameters = new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());
                holder = builder.build(signerBuilder.build(keyParameters));
            }

            return holder.toASN1Structure().getEncoded();
        } catch (Exception e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.generate_cert_err, e);
        }
    }


    public Date getNotBefore() {
        return this.cert.getNotBefore();
    }

    public Date getNotAfter() {
        return this.cert.getNotAfter();
    }

    public String getIssuerDN() {
        return this.cert.getIssuerDN().getName();
    }


    public String getSubjectDN() {
        return this.cert.getSubjectDN().getName();
    }

    public PublicKey getPublicKey() {
        return this.cert.getPublicKey();
    }

    public String getSigAlgName() {
        return this.cert.getSigAlgName();
    }


}