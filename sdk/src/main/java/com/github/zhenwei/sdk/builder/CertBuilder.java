package com.github.zhenwei.sdk.builder;

import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cert.X509v3CertificateBuilder;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.bc.BcContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcECContentSignerBuilder;
import com.github.zhenwei.pkix.operator.bc.BcRSAContentSignerBuilder;
import com.github.zhenwei.provider.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import com.github.zhenwei.provider.jce.interfaces.ECPrivateKey;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.provider.jce.spec.ECParameterSpec;
import com.github.zhenwei.sdk.enums.DigestAlgEnum;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.sdk.exception.WeGooCryptoException;
import com.github.zhenwei.sdk.util.ByteArrayUtil;
import com.github.zhenwei.sdk.util.DateUtil;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
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


    /**
     * @param [dn, publicKey, privateKey]
     * @return java.security.cert.Certificate
     * @author zhangzhenwei
     * @description 生成证书
     * @date 2022/3/15  9:09 下午
     * @since: 1.0.0
     */
    public static Certificate generateCertificate(String dn, PublicKey publicKey, PrivateKey privateKey) throws OperatorCreationException, IOException, WeGooCryptoException {
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X500Name issuer = new X500Name(dn);
        X500Name subject = new X500Name(dn);
        byte[] random = RandomBuilder.genRandom(12);
        byte[] certSn = ByteArrayUtil.mergeBytes("123".getBytes(StandardCharsets.UTF_8), random);
        BigInteger sn = new BigInteger(certSn);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, sn, DateUtil.now(), DateUtil.nowPlusDays(360), subject,keyInfo);

        String algorithm = publicKey.getAlgorithm();
        BcContentSignerBuilder signerBuilder;
        AsymmetricKeyParameter parameter;
        if (algorithm.equals(KeyPairAlgEnum.SM2_256.getAlg())) {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SM3_WITH_SM2.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SM3.getOid());
            signerBuilder = new BcECContentSignerBuilder(signAlg, digAlg);
            ECPrivateKey key = (ECPrivateKey) privateKey;
            ECParameterSpec parameters = key.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(),
                    parameters.getN(), parameters.getH(), parameters.getSeed());
            parameter = new ECPrivateKeyParameters(key.getD(), ecDomainParameters);
        } else {
            AlgorithmIdentifier signAlg = new AlgorithmIdentifier(SignAlgEnum.SHA256_WITH_RSA.getOid());
            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(DigestAlgEnum.SHA256.getOid());
            signerBuilder = new BcRSAContentSignerBuilder(signAlg, digAlg);
            BCRSAPrivateKey key = (BCRSAPrivateKey) privateKey;
            parameter = new RSAKeyParameters(true, key.getModulus(), key.getPrivateExponent());

        }

        X509CertificateHolder build = builder.build(signerBuilder.build(parameter));
        com.github.zhenwei.core.asn1.x509.Certificate certificate = build.toASN1Structure();
        return CertBuilder.getInstance(certificate.getEncoded()).getCert();
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