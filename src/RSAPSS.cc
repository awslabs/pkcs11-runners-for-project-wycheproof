// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"

static CK_MECHANISM_TYPE lookupHash(const char* hashName) {
  if (strcmp("SHA-1", hashName) == 0) {
    return CKM_SHA_1;
  }
  if (strcmp("SHA-224", hashName) == 0) {
    return CKM_SHA224;
  }
  if (strcmp("SHA-256", hashName) == 0) {
    return CKM_SHA256;
  }
  if (strcmp("SHA-384", hashName) == 0) {
    return CKM_SHA384;
  }
  if (strcmp("SHA-512", hashName) == 0) {
    return CKM_SHA512;
  }
  return 0;
}

static CK_RSA_PKCS_MGF_TYPE lookupMgf(const char* mgfName, const char* hashName) {
  assert(strcmp("MGF1", mgfName) == 0);
  if (strcmp("SHA-1", hashName) == 0) {
    return CKG_MGF1_SHA1;
  }
  if (strcmp("SHA-224", hashName) == 0) {
    return CKG_MGF1_SHA224;
  }
  if (strcmp("SHA-256", hashName) == 0) {
    return CKG_MGF1_SHA256;
  }
  if (strcmp("SHA-384", hashName) == 0) {
    return CKG_MGF1_SHA384;
  }
  if (strcmp("SHA-512", hashName) == 0) {
    return CKG_MGF1_SHA512;
  }
  return 0;
}

static GroupResult runPssGroup(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags) {
  GroupResult result = {0};
  CK_RV rv;

  CK_RSA_PKCS_PSS_PARAMS params = {0};
  CK_MECHANISM mechanism = {
    CKM_RSA_PKCS_PSS,
    &params,
    sizeof(params)
  };
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

  json_t* hashAlg = json_object_get(testGroup, "sha");
  json_t* mgfName = json_object_get(testGroup, "mgf");
  json_t* mgfHash = json_object_get(testGroup, "mgfSha");
  params.hashAlg = lookupHash(json_string_value(hashAlg));
  params.mgf = lookupMgf(json_string_value(mgfName), json_string_value(mgfHash));
  json_t* sLen = json_object_get(testGroup, "sLen");
  params.sLen = json_integer_value(sLen);
  std::cerr << json_string_value(hashAlg) << " "
	    << json_string_value(mgfName) << " "
	    << json_string_value(mgfHash) << std::endl;
  json_decref(mgfName);

  json_t* testArray = json_object_get(testGroup, "tests");
  assert(testArray);
  assert(json_is_array(testArray));

  std::cerr << std::hex << "0x" << params.hashAlg << " "
	    << "0x" << params.mgf << " "
	    << std::dec << params.sLen << std::endl;


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
	      << "RV=" << std::hex << rv << " " << std::dec
	      << json_string_value(comment) << std::endl;
    json_decref(tcId);
    json_decref(comment);
    json_decref(msgHex);
    json_decref(sigHex);
    free(msg);
    free(sig);
    //  return result;
  }

  json_decref(sLen);
  json_decref(mgfHash);
  json_decref(hashAlg);
  return result;
}

groupFunction rsaPssRunGroup = &runPssGroup;
