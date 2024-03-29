package com.github.zhenwei.pkix.mime.smime;

import com.github.zhenwei.pkix.mime.MimeParserContext;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;

public class SMimeParserContext
    implements MimeParserContext {

  private final String defaultContentTransferEncoding;
  private final DigestCalculatorProvider digestCalculatorProvider;

  public SMimeParserContext(String defaultContentTransferEncoding,
      DigestCalculatorProvider digestCalculatorProvider) {
    this.defaultContentTransferEncoding = defaultContentTransferEncoding;
    this.digestCalculatorProvider = digestCalculatorProvider;
  }

  public String getDefaultContentTransferEncoding() {
    return defaultContentTransferEncoding;
  }

  public DigestCalculatorProvider getDigestCalculatorProvider() {
    return digestCalculatorProvider;
  }
}