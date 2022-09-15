package com.github.zhenwei.test.key;

import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.enums.exception.CryptoExceptionMassageEnum;
import com.github.zhenwei.core.exception.WeGooCryptoException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import org.junit.Test;

public class Pkcs7Test {


    private static final String rsa_cert = "MIICqTCCAhKgAwIBAgINK18X49nTNGMoqUqg4DANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTENMAsGA1UEAwwEWFhYWDAeFw0yMDA3MjIwNjU5MzdaFw0yMTA3MjIwNjU5MzdaMGExCzAJBgNVBAYMAkNOMS0wKwYDVQQKDCTlub/kuJzlro/lpKfmsJHniIbpm4blm6LmnInpmZDlhazlj7gxDzANBgNVBAsMBuadjuS5pjESMBAGA1UEAwwJ5Zub5bed55yBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDU+qVhhBu9CAWN/4oJuHkBsCYmlYBneOFULbwj6yLo/D3vYKI/legYVhdAVUj2EJilLJ/pKUh351DuP7JEF1pDiREc7cC4fsiLylFJe3imPxuvRmgWq7rXI9xRGeJ4Pfo3l0tUeTeH417Y4yq8rJNyzOPiDtMGPW4AsQ69fYi64QIDAQABo4GLMIGIMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUB5geefFYEHvYFNyRcsQHwYXOrPQwHwYDVR0jBBgwFoAU/g7wGnRqNakWoXChWcWOFNgtrmwwOQYDVR0gBDIwMDAuBgIpATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vMTI3LjAuMC4xOjkwOTAvcGF0aDANBgkqhkiG9w0BAQUFAAOBgQC+lL4SvAYIKTLimbcOamvPpJbpnai3HXv9Xv+Sf8IFvQ4HfbsPeUNj/i4Wu1i9gKULUOufECkc3o4ICLoZoArFa+BgeMtyRmcUgBJ5SLHBq+teO/92jEbLaL8DdYwGleS49MFoCWC47TKfrWgFNhq+/D4Dqb/OidutTDwRvGrECg==";
    private static final String rsa_pri = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANT6pWGEG70IBY3/igm4eQGwJiaVgGd44VQtvCPrIuj8Pe9goj+V6BhWF0BVSPYQmKUsn+kpSHfnUO4/skQXWkOJERztwLh+yIvKUUl7eKY/G69GaBarutcj3FEZ4ng9+jeXS1R5N4fjXtjjKrysk3LM4+IO0wY9bgCxDr19iLrhAgMBAAECgYAcLiP20LOY4fhWLxM1MQ71zbhmj46DYmeyKzEDMagXWtTZGRiuwCeLHM0Lyp0STeTcqhhokflQQC+hrpToVIyxOBgV2vE6bh51J8sf1IKvLMq50CZd2fEt9aYRu741mEQ5/J/lT6o3hy2VIp+0aTYAsEjVJ7w5ukjAGAE2cyLcdwJBAPNF6zphbcunalgIsnUZ17J30dSdSawzmB5eokd/5MMparx2c1/uRB6H/ajFwMax5HfBsTZfVvMxwfeZBBByHrMCQQDgHwIy7y+PCsY+3NxLVVMl69Yn/ySrXDS89F1kE+tln8V+U+3ZuXjeCHV1rerDUDjfZjJOCqG9NZsuCH6IwYobAkEA4qWnjBKtemmVeENSECttfAaJ5a5MrzS6asD8K+UJupHhsYgh4aRYrqFAQHdNLVEbbD923RNiLN2UuxtCYBgSZQJAFwyZWUuoBHoDMWvdbBH2XywF9k8TIlx1QAmRoT07NFReJ0PSblXYzFzqV5PvVO7nKnKEMep9/8uHjhBpkv70iQJASDp4Rb+MLJYJ4aiCVd8mtwi9W9AqlHuqSm1qfTmPbaksYN1NJRmJt2yTi63LUNpfJAbU2M7X58L6BVwBM6L3Ug==";

    private static final String sm2_cert = "MIICVDCCAfigAwIBAgINK18ZO7bTNGMoqUqg4jAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDcyMzA3MjY0NloXDTIxMDcyMzA3MjY0NlowYTELMAkGA1UEBgwCQ04xLTArBgNVBAoMJOW5v+S4nOWuj+Wkp+awkeeIhumbhuWbouaciemZkOWFrOWPuDEPMA0GA1UECwwG5p2O5LmmMRIwEAYDVQQDDAnlm5vlt53nnIEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR7JZ4/mEtcesvKGd+AJ0j5Jpbgfh2oD1pVc7D1Ku6Hqso0NEQf8XJKx1Ea8emHJJI/qyntNhd7cW8p4sHyasmWo4GSMIGPMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUWWmvtdOg8HEF9P2LCRrcG/Xru50wHwYDVR0jBBgwFoAUzGckQhrD+K0nrNLy5YSBH+nFL64wQAYDVR0gBDkwNzA1BgkqgRyG7zICAgIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwDAYIKoEcz1UBg3UFAANIADBFAiBJKVi5bkVWiqDFVGpuHok4FA9N+u1bZzFAQwrrJFJNmAIhANeMDMm38jp+oxZUCsShqq98CKz5EvjKF0s+RUqxBOzK";
    private static final String sm2_pri = "pT3ASc9wG3rO2Xx6MX6CaWcVAtqxrtPbGt8x7fyQ7a8=";



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
//        GmPkcs7Builder gmPkcs7Builder = new GmPkcs7Builder();
//        Certificate[] cers = new Certificate[]{
//            CertBuilder.getInstance(Base64.decode(rsa_cert)).getCert0()
//        };
//        ContentInfo contentInfo = gmPkcs7Builder.genPkcs7ContentInfo(
//            Pkcs7ContentInfoTypeEnum.SIGNED_DATA, "3123".getBytes(
//                StandardCharsets.UTF_8), SignAlgEnum.SHA256_WITH_RSA, new byte[32], cers, null, true);
//        System.out.println(Hex.toHexString(contentInfo.getEncoded()));

    }

}
