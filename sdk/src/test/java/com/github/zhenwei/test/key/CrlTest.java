package com.github.zhenwei.test.key;

import com.github.zhenwei.sdk.builder.CrlBuilder;
import java.io.File;
import java.io.FileInputStream;
import org.junit.Test;

public class CrlTest {

  @Test
  public void parseCrl() throws Exception {
    FileInputStream fileInputStream = new FileInputStream(new File("/"));
    CrlBuilder builder = CrlBuilder.getInstance(fileInputStream);
    String crlIssue = builder.getCrlIssue();
  }

}