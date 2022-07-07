package com.github.zhenwei.pkix.mime.smime;

import com.github.zhenwei.pkix.mime.BasicMimeParser;
import com.github.zhenwei.pkix.mime.Headers;
import com.github.zhenwei.pkix.mime.MimeParser;
import com.github.zhenwei.pkix.mime.MimeParserProvider;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import java.io.IOException;
import java.io.InputStream;

public class SMimeParserProvider
    implements MimeParserProvider {

  private final String defaultContentTransferEncoding;
  private final DigestCalculatorProvider digestCalculatorProvider;

  public SMimeParserProvider(String defaultContentTransferEncoding,
      DigestCalculatorProvider digestCalculatorProvider) {
    this.defaultContentTransferEncoding = defaultContentTransferEncoding;
    this.digestCalculatorProvider = digestCalculatorProvider;
  }

  public MimeParser createParser(InputStream source)
      throws IOException {
    return new BasicMimeParser(
        new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
        SMimeUtils.autoBuffer(source));
  }

  public MimeParser createParser(Headers headers, InputStream source)
      throws IOException {
    return new BasicMimeParser(
        new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
        headers, SMimeUtils.autoBuffer(source));
  }
}