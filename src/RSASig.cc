// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"

static GroupResult runGroup(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags) {
  GroupResult result = {0};
  CK_RV rv;
  CK_MECHANISM mechanism = {
    CKM_SHA256_RSA_PKCS,
    NULL,
    0
  };
  {
    json_t* shaType;
    json_object_get_string(shaType, testGroup, "sha");
    if (strcmp("SHA-256", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_SHA256_RSA_PKCS;
    } else if (strcmp("SHA-1", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_SHA1_RSA_PKCS;
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

  json_t* pubExp = json_object_get(testGroup, "e");
  assert(pubExp);
  assert(json_is_string(pubExp));
  json_t* modulus = json_object_get(testGroup, "n");
  assert(modulus);
  assert(json_is_string(modulus));
  CK_OBJECT_HANDLE key = importRsaKey(pFunctionList, session,
				      json_string_value(pubExp), json_string_value(modulus));
  std::cerr << "Imported key: " << key << std::endl;
  json_decref(pubExp);
  json_decref(modulus);
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
    result.totalTests++;

    tcId = json_object_get(testCase, "tcId");
    assert(tcId && json_is_integer(tcId));
    json_object_get_string(comment, testCase, "comment");
    json_object_get_string(msgHex, testCase, "msg");
    json_object_get_string(sigHex, testCase, "sig");

    msgSize = parseHex(json_string_value(msgHex), &msg);
    assert(msg);
    sigSize = parseHex(json_string_value(sigHex), &sig);
    assert(sig);

    P11_ASSERT(pFunctionList->C_VerifyInit(session, &mechanism, key));
    CK_RV rv = pFunctionList->C_Verify(session, msg, msgSize, sig, sigSize);
    const char* resultHeader;
    if ((rv == CKR_OK) != expectSuccess) {
      resultHeader = "\e[91m[FAILED]\e[0m  ";
      result.failures++;
      printArr(msg, msgSize);
      printf("\n");
      printArr(sig, sigSize);
      printf("\n");
    } else {
      resultHeader = "\e[92m[SUCCESS]\e[0m ";
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

groupFunction rsaSigRunGroup = &runGroup;
