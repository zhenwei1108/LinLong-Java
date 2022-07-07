package com.github.zhenwei.test.key;

import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.builder.P10Builder;
import com.github.zhenwei.sdk.builder.params.CertExtension;
import com.github.zhenwei.sdk.builder.params.CodingType;
import com.github.zhenwei.core.enums.KeyPairAlgEnum;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class P10Test {

    @Test
    public void genP10() throws Exception {
        WeGooProvider provider = new WeGooProvider();
        KeyBuilder keyBuilder = new KeyBuilder(provider);
        KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.SM2_256);
        List<CertExtension> list = new ArrayList<>();
        CertExtension certExtension = new CertExtension("1.2.3", "demo1111".getBytes(StandardCharsets.UTF_8), CodingType.DEROCTETSTRING);
        list.add(certExtension);
        P10Builder p10Builder = new P10Builder("C=CN,CN=TEST", keyPair.getPublic(), keyPair.getPrivate(), list);
        String p10 = p10Builder.getP10();
        System.out.println(p10);

    }

}
