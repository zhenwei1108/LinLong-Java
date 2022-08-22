package com.github.zhenwei.test.key;

import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.asn1.pkcs.ContentInfo;
import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.core.enums.GmPkcs7ContentInfoTypeEnum;
import com.github.zhenwei.core.enums.SignAlgEnum;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import com.github.zhenwei.core.util.encoders.Base64;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.sdk.builder.CertBuilder;
import com.github.zhenwei.sdk.builder.pkcs7.GmPkcs7Builder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class Pkcs7Test {

    String cert = "MIICVDCCAfigAwIBAgINK18ZO7bTNGMoqUqg4jAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDcyMzA3MjY0NloXDTIxMDcyMzA3MjY0NlowYTELMAkGA1UEBgwCQ04xLTArBgNVBAoMJOW5v+S4nOWuj+Wkp+awkeeIhumbhuWbouaciemZkOWFrOWPuDEPMA0GA1UECwwG5p2O5LmmMRIwEAYDVQQDDAnlm5vlt53nnIEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR7JZ4/mEtcesvKGd+AJ0j5Jpbgfh2oD1pVc7D1Ku6Hqso0NEQf8XJKx1Ea8emHJJI/qyntNhd7cW8p4sHyasmWo4GSMIGPMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUWWmvtdOg8HEF9P2LCRrcG/Xru50wHwYDVR0jBBgwFoAUzGckQhrD+K0nrNLy5YSBH+nFL64wQAYDVR0gBDkwNzA1BgkqgRyG7zICAgIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwDAYIKoEcz1UBg3UFAANIADBFAiBJKVi5bkVWiqDFVGpuHok4FA9N+u1bZzFAQwrrJFJNmAIhANeMDMm38jp+oxZUCsShqq98CKz5EvjKF0s+RUqxBOzK";



    @Test
    public void bigFileData() throws WeGooCryptoException {
        try {
            File file = new File("/Users/zhangzhenwei/jmeter.log");
            FileInputStream inputStream = new FileInputStream(file);
            ASN1InputStream asn1InputStream = new ASN1InputStream(inputStream);
            byte[] data = new byte[asn1InputStream.available()];
            inputStream.read(data);
            BEROctetString berOctetString = new BEROctetString(data,256);
            byte[] encoded = berOctetString.getEncoded(ASN1Encoding.BER);
            File file1 = new File("/Users/zhangzhenwei/encodeber.txt");
            FileOutputStream fileOutputStream = new FileOutputStream(file1);
            fileOutputStream.write(encoded);
        } catch (IOException e) {
            throw new WeGooCryptoException(CryptoExceptionMassageEnum.gen_pkcs7_data_err, e);
        }
    }


    @Test
    public void pkcs7SignedData() throws WeGooCryptoException, IOException {
        GmPkcs7Builder gmPkcs7Builder = new GmPkcs7Builder();
        Certificate[] cers = new Certificate[]{
            CertBuilder.getInstance(Base64.decode(cert)).getCert0()
        };
        ContentInfo contentInfo = gmPkcs7Builder.genPkcs7ContentInfo(
            GmPkcs7ContentInfoTypeEnum.SIGNED_DATA, "3123".getBytes(
                StandardCharsets.UTF_8), SignAlgEnum.SM3_WITH_SM2, new byte[32], cers, null, true);
        System.out.println(Hex.toHexString(contentInfo.getEncoded()));
    }

}
