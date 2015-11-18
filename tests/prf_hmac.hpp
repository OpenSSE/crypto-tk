#pragma once

/*******
*  prf_mac.cpp
*
*  Implementation of the HMAC's test vector verification.
*  Reference vectors are taken from RFC 4231 [https://tools.ietf.org/html/rfc4231]
*  Only the first four test cases are implemented: 
*  the HMAC-based PRF implementation does not support keys larger than 64 bytes
********/	

bool hmac_tests();
bool hmac_test_case_1();
bool hmac_test_case_2();
bool hmac_test_case_3();
bool hmac_test_case_4();
