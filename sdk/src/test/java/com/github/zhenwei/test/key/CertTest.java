package com.github.zhenwei.test.key;

import com.github.zhenwei.sdk.builder.CertBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.util.Date;

public class CertTest {


  public static void main(String[] args) throws Exception {
    CertBuilder builder = CertBuilder.getInstance(new FileInputStream(new File("")));
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
  }


}