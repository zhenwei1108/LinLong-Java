package com.github.zhenwei.test.key;

import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.CertBuilder;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.builder.KeyStoreBuilder;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.util.Base64Util;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeyStoreTest {

    @Test
    public void genJks() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder();
        KeyBuilder keyBuilder = new KeyBuilder(new WeGooProvider());
        KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
        byte[] certificate = CertBuilder.generateCertificate("","C=CN,CN=demo", keyPair.getPublic(), keyPair.getPrivate());
        System.out.println("证书："+ Base64Util.encode(certificate));
        System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));
        X509Certificate cert = CertBuilder.getInstance(certificate).getCert();
        byte[] jks = builder.genJks(keyPair.getPrivate(), "test", "123123", new Certificate[]{cert});
        System.out.println(Hex.toHexString(jks));


    }


}
