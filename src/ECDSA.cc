// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"
#include <openssl/x509.h>

static GroupResult runGroup(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags) {
  GroupResult result = {0};
  CK_RV rv;
  CK_MECHANISM mechanism = {
    CKM_ECDSA_SHA1,
    NULL,
    0
  };
  {
    json_t* shaType;
    json_object_get_string(shaType, testGroup, "sha");
    if (strcmp("SHA-256", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_ECDSA_SHA256;
    } else if (strcmp("SHA-1", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_ECDSA_SHA1;
    } else if (strcmp("SHA-224", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_ECDSA_SHA224;
    } else if (strcmp("SHA-384", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_ECDSA_SHA384;
    } else if (strcmp("SHA-512", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_ECDSA_SHA512;
    } else {
      assert(false);
    }
    json_decref(shaType);
  }
  // Check for Mechanism support
  {
    CK_MECHANISM_INFO mechInfo;
    rv = pFunctionList->C_GetMechanismInfo(slot, mechanism.mechanism, &mechInfo);
    if (rv != CKR_OK) {
      return result;
    }
  }
  json_t* keyDer;
  json_object_get_string(keyDer, testGroup, "keyDer");

  CK_OBJECT_HANDLE key = importEcKey(pFunctionList, session,
				     json_string_value(keyDer));
  json_decref(keyDer);

  std::cerr << "Imported key: " << key << std::endl;

  json_t* testArray = json_object_get(testGroup, "tests");
  assert(testArray);
  assert(json_is_array(testArray));
  size_t testCount = json_array_size(testArray);
  for (size_t idx = 0; idx < testCount; ++idx) {
    json_t* testCase;
    bool expectSuccess;
    json_t* testResult;
    json_t* tcId;
    json_t* comment;
    json_t* msgHex;
    json_t* sigHex;
    CK_BYTE_PTR msg, sig;
    size_t msgSize, sigSize;

    testCase = json_array_get(testArray, idx);
    assert(testCase);
    assert(json_is_object(testCase));
    testResult = json_object_get(testCase, "result");
    const char* resultStr = json_string_value(testResult);
    if (strcmp(resultStr, "acceptable") == 0) {
      json_decref(testResult);
      json_decref(testCase);
      continue;
    } else {
      expectSuccess = strcmp(resultStr, "valid") == 0;
      json_decref(testResult);
    }
    json_object_get_string(sigHex, testCase, "sig");
    {
      CK_BYTE_PTR tmpPtr, tmpSig, r, s;
      unsigned char rLen, sLen;
      size_t partLen;
      const char* tmpHex = json_string_value(sigHex);
      sigSize = parseHex(tmpHex, &tmpSig);
      assert(tmpSig);
      sigSize = parseAsn1DsaSig(tmpSig, sigSize, &sig);
      free(tmpSig);
      if (sigSize == 0) {
	continue;
      }
    }
    result.totalTests++;

    tcId = json_object_get(testCase, "tcId");
    assert(tcId && json_is_integer(tcId));
    json_object_get_string(comment, testCase, "comment");
    json_object_get_string(msgHex, testCase, "msg");

    msgSize = parseHex(json_string_value(msgHex), &msg);
    assert(msg);
    //    sigSize = parseHex(json_string_value(sigHex), &sig);
    //    assert(sig);

    std::cout << "[STARTING]                  " << groupIdx << json_integer_value(tcId) << std::endl;

    P11_ASSERT(pFunctionList->C_VerifyInit(session, &mechanism, key));
    rv = pFunctionList->C_Verify(session, msg, msgSize, sig, sigSize);
    char resultHeader[64];
    if ((rv == CKR_OK) != expectSuccess) {
      snprintf(resultHeader, sizeof(resultHeader) - 1, "\e[91m[FAILED](%#016lx)\e[0m  ", rv);
      result.failures++;
            printArr(msg, msgSize);
            printf("\n");
            printArr(sig, sigSize);
            printf("\n");
    } else {
      snprintf(resultHeader, sizeof(resultHeader) - 1, "\e[92m[SUCCESS](%#016lx)\e[0m ", rv);
      result.passes++;
    }
    std::cout << resultHeader << groupIdx << ":"
	      << json_integer_value(tcId) << " "
	      << json_string_value(comment) << std::endl;
    json_decref(tcId);
    json_decref(comment);
    json_decref(msgHex);
    json_decref(sigHex);
    free(msg);
    free(sig);
    //  return result;
  }
				      
  return result;
}

groupFunction ecdsaRunGroup = &runGroup;
