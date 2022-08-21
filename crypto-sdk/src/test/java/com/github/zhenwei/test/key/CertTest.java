package com.github.zhenwei.test.key;

import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.CertBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class CertTest {


    @Test
    public void parseCert() throws Exception {
//        CertBuilder builder = CertBuilder.getInstance(new FileInputStream(new File("")));
        Certificate cert = genCert();
        CertBuilder builder = CertBuilder.getInstance(cert.getEncoded());
        String certSn = builder.getCertSn();
        System.out.println(certSn);
        String issuerDN = builder.getIssuerDN();
        System.out.println(issuerDN);
        String subjectDN = builder.getSubjectDN();
        System.out.println(subjectDN);
        Date notAfter = builder.getNotAfter();
        System.out.println(notAfter);
        String sigAlgName = builder.getSigAlgName();
        System.out.println(sigAlgName);
        String algorithm = builder.getPublicKey().getAlgorithm();
        System.out.println(algorithm);
    }


    public Certificate genCert() throws Exception {
        KeyBuilder keyBuilder = new KeyBuilder();
        KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
        SignAlgEnum signAlgEnum = SignAlgEnum.SM3_WITH_SM2;
        byte[] certificate = CertBuilder.generateCertificate("O=zhenwei,CN=wegoo,C=CN","O=zhenwei,CN=wegoo,C=CN", keyPair.getPublic(), keyPair.getPrivate(),signAlgEnum,1, TimeUnit.DAYS);
        CertBuilder builder = CertBuilder.getInstance(certificate);
        return builder.getCert();

    }


}