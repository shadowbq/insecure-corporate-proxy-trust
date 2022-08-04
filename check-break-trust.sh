#!/usr/bin/env bash
if [[ $(echo "Q" |openssl s_client -connect pypi.python.org:443 2>/dev/null) == *"Verification error"* ]]; then
  echo "Full Break Proxy Detected"
fi
