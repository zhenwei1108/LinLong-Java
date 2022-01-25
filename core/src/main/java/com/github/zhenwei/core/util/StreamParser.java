package com.github.zhenwei.core.util;

import java.util.Collection;

public interface StreamParser {

  Object read() throws StreamParsingException;

  Collection readAll() throws StreamParsingException;
}