package com.github.zhenwei.pkix.cms;

import com.github.zhenwei.core.util.io.TeeInputStream;
import com.github.zhenwei.pkix.operator.InputAEADDecryptor;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.pkix.operator.MacCalculator;
import java.io.InputStream;
import java.io.OutputStream;

public class RecipientOperator {

  private final Object operator;

  public RecipientOperator(InputDecryptor decryptor) {
    this.operator = decryptor;
  }

  public RecipientOperator(MacCalculator macCalculator) {
    this.operator = macCalculator;
  }

  public InputStream getInputStream(InputStream dataIn) {
    if (operator instanceof InputDecryptor) {
      return ((InputDecryptor) operator).getInputStream(dataIn);
    } else {
      return new TeeInputStream(dataIn, ((MacCalculator) operator).getOutputStream());
    }
  }

  public boolean isAEADBased() {
    return operator instanceof InputAEADDecryptor;
  }

  public OutputStream getAADStream() {
    return ((InputAEADDecryptor) operator).getAADStream();
  }

  public boolean isMacBased() {
    return operator instanceof MacCalculator;
  }

  public byte[] getMac() {
    return ((MacCalculator) operator).getMac();
  }
}