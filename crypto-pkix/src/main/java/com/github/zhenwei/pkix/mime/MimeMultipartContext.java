package com.github.zhenwei.pkix.mime;

import java.io.IOException;

public interface MimeMultipartContext
    extends MimeContext {

  public MimeContext createContext(int partNo)
      throws IOException;
}