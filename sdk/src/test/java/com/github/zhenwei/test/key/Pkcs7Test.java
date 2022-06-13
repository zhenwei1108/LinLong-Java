package com.github.zhenwei.test.key;

import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.GmPkcs7ContentInfoTypeEnum;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.sdk.builder.CertBuilder;
import com.github.zhenwei.sdk.builder.PKCS7Builder;
import com.github.zhenwei.sdk.util.Base64Util;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class Pkcs7Test {

    String cert = "MIICVDCCAfigAwIBAgINK18ZO7bTNGMoqUqg4jAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDcyMzA3MjY0NloXDTIxMDcyMzA3MjY0NlowYTELMAkGA1UEBgwCQ04xLTArBgNVBAoMJOW5v+S4nOWuj+Wkp+awkeeIhumbhuWbouaciemZkOWFrOWPuDEPMA0GA1UECwwG5p2O5LmmMRIwEAYDVQQDDAnlm5vlt53nnIEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR7JZ4/mEtcesvKGd+AJ0j5Jpbgfh2oD1pVc7D1Ku6Hqso0NEQf8XJKx1Ea8emHJJI/qyntNhd7cW8p4sHyasmWo4GSMIGPMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUWWmvtdOg8HEF9P2LCRrcG/Xru50wHwYDVR0jBBgwFoAUzGckQhrD+K0nrNLy5YSBH+nFL64wQAYDVR0gBDkwNzA1BgkqgRyG7zICAgIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwDAYIKoEcz1UBg3UFAANIADBFAiBJKVi5bkVWiqDFVGpuHok4FA9N+u1bZzFAQwrrJFJNmAIhANeMDMm38jp+oxZUCsShqq98CKz5EvjKF0s+RUqxBOzK";


    @Test
    public void genSignedData() throws Exception {
        PKCS7Builder builder = new PKCS7Builder();
        CertBuilder certBuilder = CertBuilder.getInstance(Base64Util.decode(cert));
        Certificate[] certificates = new Certificate[]{certBuilder.getCert0()};
        byte[] signedData = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
        ContentInfo info = builder.build(GmPkcs7ContentInfoTypeEnum.SIGNED_DATA, "asdfasdfasdfwerq".getBytes(StandardCharsets.UTF_8), SignAlgEnum.SM3_WITH_SM2, signedData, certificates, null);
        byte[] encoded = info.getEncoded(ASN1Encoding.BER);
        System.out.println(Base64Util.encode(encoded));

    }

}
