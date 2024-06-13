# XSS Test Payload
XSS_TEST_PAYLOAD = "<script>alert('XSS')</script>"


class XSSConfig:
    ENCODE_XSS = False
    BLIND_XSS = False
    FUZZ_XSS = False


xss_config = XSSConfig()
