// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"
#include <openssl/x509.h>

CK_OBJECT_HANDLE importDsaKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
			      const char* primeHex, const char* subPrimeHex,
			      const char* baseHex, const char* valueHex) {

  CK_BYTE_PTR prime, tmpPrime, subPrime, tmpSubPrime, base, tmpBase, value, tmpValue;
  size_t primeLen, subPrimeLen, baseLen, valueLen;
  CK_OBJECT_HANDLE result = -1;
  primeLen = parseHex(primeHex, &prime);
  tmpPrime = prime;
  subPrimeLen = parseHex(subPrimeHex, &subPrime);
  tmpSubPrime = subPrime;
  baseLen = parseHex(baseHex, &base);
  tmpBase = base;
  valueLen = parseHex(valueHex, &value);
  tmpValue = value;

  if (prime[0] == 0) {
    tmpPrime++;
    primeLen--;
  }
  if (subPrime[0] == 0) {
    tmpSubPrime++;
    subPrimeLen--;
  }
  if (base[0] == 0) {
    tmpBase++;
    baseLen--;
  }
  if (value[0] == 0) {
    tmpValue++;
    valueLen--;
  }

  CK_ATTRIBUTE import[] = {
    {CKA_PRIME, tmpPrime, primeLen},
    {CKA_SUBPRIME, tmpSubPrime, subPrimeLen},
    {CKA_BASE, tmpBase, baseLen},
    {CKA_VALUE, tmpValue, valueLen},
    ATTR_LOCAL_CONST(CKA_CLASS, CKO_PUBLIC_KEY, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_KEY_TYPE, CKK_DSA, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_VERIFY, CK_TRUE, CK_BBOOL)
  };
  printTemplate(import, sizeofTemplate(import));
  P11_ASSERT(pFunctionList->C_CreateObject(session, import, sizeofTemplate(import), &result));

  free(prime);
  free(subPrime);
  free(base);
  free(value);
  return result;
}


static GroupResult runGroup(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags) {
  GroupResult result = {0};
  CK_RV rv;
  CK_MECHANISM mechanism = {
    CKM_DSA_SHA1,
    NULL,
    0
  };
  {
    json_t* shaType;
    json_object_get_string(shaType, testGroup, "sha");
    if (strcmp("SHA-256", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_DSA_SHA256;
    } else if (strcmp("SHA-1", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_DSA_SHA1;
    } else if (strcmp("SHA-224", json_string_value(shaType)) == 0) {
      mechanism.mechanism = CKM_DSA_SHA224;
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
  json_t* keyJson = json_object_get(testGroup, "key");
  assert(keyJson);
  assert(json_is_object(keyJson));
  json_t* prime;
  json_t* subPrime;
  json_t* base;
  json_t* value;
  json_object_get_string(prime, keyJson, "p");
  json_object_get_string(subPrime, keyJson, "q");
  json_object_get_string(base, keyJson, "g");
  json_object_get_string(value, keyJson, "y");
  CK_OBJECT_HANDLE key = importDsaKey(pFunctionList, session,
				      json_string_value(prime), json_string_value(subPrime),
				      json_string_value(base), json_string_value(value));
  std::cerr << "Imported key: " << key << std::endl;
  json_decref(prime);
  json_decref(subPrime);
  json_decref(base);
  json_decref(value);
  json_decref(keyJson);
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

groupFunction dsaRunGroup = &runGroup;
