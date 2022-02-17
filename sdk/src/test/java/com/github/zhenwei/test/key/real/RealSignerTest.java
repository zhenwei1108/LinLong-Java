package com.github.zhenwei.test.key.real;

import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.provider.jce.provider.WeGooProvider;
import com.github.zhenwei.sdk.builder.KeyBuilder;
import com.github.zhenwei.sdk.builder.SignBuilder;
import com.github.zhenwei.sdk.enums.KeyPairAlgEnum;
import com.github.zhenwei.sdk.enums.SignAlgEnum;
import com.github.zhenwei.sdk.exception.BaseWeGooException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.Test;

public class RealSignerTest {

  /**
   * 私钥
   */
  String pri = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0edOGtz95UOIT2ue3KOkYSATtUz+ZPRMn7QIJE2e82m1U1h1yPRO/5A7rfC/XsRyk2n+o8NJT2B8x9P53/RZnw9KM+epITMbkf1w0KMls+tOB6XCtUhLC+awWs6pbkVoaGUdHC7CkTHEHtU95ANIR2UoKf5tGsiXfbRP2dGvN2A4dzXlPi4ZBuShf2Wa0UDwVTRBwSKqHGLs09W6HJhmCLHrP35lj5mSVDfylrgHOtH1uQ3jDNrzr1IxLTWtvWVF23xsLpzmghnS450B3U99LvBPXufbbAGC49qpjSpwucIjFDquYUf7GPVtpMLTXgtkxUTeNXj5T3pXyNCy7LUmVAgMBAAECggEAAUYJNpRRv97GfXzmN8oIHkTJmTvIwoz0gUBX9VVlzZxpeJ87JnIHagzEwGzTr68DuFUjW+Mz+MRMT5PwigOWfAJA4HCGkVw03LSSqKOSAUcdIqrrIvWoblDskoZcIc1Kdyn2qcOGeZbSG3SJxf6BpfUoG+IOpWs6+f03d5E1eYu+TCM6RnVfke2GmnHVIx35dQR7v7wkl6pqYNAtNRlIMIBkkQB/7+aaaVwHv9gLtZWI3j5OCI3lvXMtNiGZe7Y0zIVF9zkOoIHekBoUQHoAa8gtEUnvxbtLyD3WAZppPfEUf+HiwLnMtBwQxRM5w/a5pQYIVDhdghZ+RQzwTLy2OQKBgQDY+EfR+CwousIJzQgDkZZCJ0WutFIj3rSyJOk6EXSEpwaDPie+UA0+s6f9ha1kM82ZYXwf9u3S+a9sOzo3hPWnp2drVaMMlITyxYWONiKa7O1+Fq/evS+NNAQEOQAWxyR6h6rleCxvHOxtFfJEqhAPlz34WceqtJNqoGqDQRZedwKBgQDU8PSTUm4j2+nZutRz7LSy4db0aViyg+tXB3Ws9NMwDg+4tl65xsMwFhJw0ybm69Ov9pBIYWyIFmR7feQIi5L8IPPaNrZSLPzXWB/ULYX4gCGtQSuEIROybiHOX+h/c4/2gLVB3japCp99Ql/kx9AhpIcNEO3JkuTEIH8BmjXfUwKBgEY+y/Hc6V8eZ+gIa4nMPtuYH2VamCVo2xO6A5B7SkAQW3luTCu/eypLvB3Gg8anRu9bsnYe2gyuLe9alZSYBXiMKF2F0k4mX4zCCmVqfXWvM4zZB4OTuKt8pbhARBkbzGGnPtsgNzKaKKmAq3kznhOOIdAgMRbBc+DXouRv1DAtAoGBAJ9wt8BjdSKWdDfaA1+1eeuC3D9vbcFks18br8nMGyEdNjpZGv5BTD8CF9aw060OIRfdJ1V61RfkpGIu9gJL98efKNdYJhXLp5naWyK0314dGpoudNXfKm9stRVgjKZ5se6hmpZyOz1BPgA9Ja4YyseV+KUY6uMGgRI1PsPFYtcPAoGAIIfXuBJmV+fC+5LVt3iNRMan/KWbKK+CsolldhB4iFqKRolzULnBxv1eq6i6DFEQ29Ai6rz8EK7W5RL6mvx45wOYNU2P/uwE7xP/eDVBzfUkpCvDtbC93OvVowbFSaFajM44pqPfixEFTaC4u4PpuMnmcGCe6pNTa6L3qAp8HQ8=";

  @Test
  public void readSigner() throws BaseWeGooException {
    WeGooProvider weGooProvider = new WeGooProvider();
    SignBuilder signBuilder = new SignBuilder(weGooProvider);
    KeyBuilder keyBuilder = new KeyBuilder(weGooProvider);
    KeyPair keyPair = keyBuilder.buildKeyPair(KeyPairAlgEnum.RSA_1024);
    byte[] data = signBuilder.signatureSourceData(SignAlgEnum.SHA256_WITH_RSA, keyPair.getPrivate(),
        "asdfa".getBytes(  StandardCharsets.UTF_8));
    System.out.println(Hex.toHexString(data));

  }



}