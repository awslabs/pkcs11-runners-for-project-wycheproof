// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"

static GroupResult runAesCbcPadGroup(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags) {
  GroupResult result = {0};
  CK_BYTE scratch[4096];
  CK_ULONG scratchSize = sizeof(scratch);
  CK_RV rv;
  CK_MECHANISM mechanism = {
    CKM_AES_CBC_PAD,
    NULL,
    0
  };

  // Check for Mechanism support
  {
    CK_MECHANISM_INFO mechInfo;
    rv = pFunctionList->C_GetMechanismInfo(slot, mechanism.mechanism, &mechInfo);
    if (rv != CKR_OK) {
      return result;
    }
  }

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
    json_t* keyHex;
    json_t* ivHex;
    json_t* msgHex;
    json_t* ctHex;
    CK_BYTE_PTR msg, ct, iv;
    size_t msgSize, ctSize, ivSize;

    testCase = json_array_get(testArray, idx);
    assert(testCase);
    assert(json_is_object(testCase));
    testResult = json_object_get(testCase, "result");
    const char* resultStr = json_string_value(testResult);
    if (strcmp(resultStr, "acceptable") == 0 || shouldSkip(testCase, ignoredFlags)) {
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
    json_object_get_string(ctHex, testCase, "ct");
    json_object_get_string(ivHex, testCase, "iv");
    json_object_get_string(keyHex, testCase, "key");

    msgSize = parseHex(json_string_value(msgHex), &msg);
    assert(msg);
    ctSize = parseHex(json_string_value(ctHex), &ct);
    assert(ct);
    ivSize = parseHex(json_string_value(ivHex), &iv);
    assert(iv);

    CK_OBJECT_HANDLE keyHandle = importSymmetricCryptoKey(
							  pFunctionList,
							  session,
							  CKK_AES,
							  json_string_value(keyHex));

    mechanism.pParameter = iv;
    mechanism.ulParameterLen = ivSize;

    P11_ASSERT(pFunctionList->C_DecryptInit(session, &mechanism, keyHandle));
    scratchSize = sizeof(scratch);
    CK_RV rv = pFunctionList->C_Decrypt(session, ct, ctSize, scratch, &scratchSize);

    const char* resultHeader;
    if (!expectSuccess) {
      if (rv == CKR_OK) {
	resultHeader = "\e[91m[FAILED]\e[0m          ";
	result.failures++;
      } else {
	resultHeader = "\e[92m[SUCCESS]\e[0m         ";
	result.passes++;
      }
    } else {
      if (rv != CKR_OK) {
	resultHeader = "\e[91m[FAILED]\e[0m Bad CKR  ";
	result.failures++;
      } else {
	// Check ciphertext
	if (memcmp(msg, scratch, scratchSize) == 0) {
	  resultHeader = "\e[92m[SUCCESS]\e[0m         ";
	  result.passes++;
	} else {
	  resultHeader = "\e[91m[FAILED]\e[0m Bad PT   ";
	  result.failures++;
	}
      }
    }

    std::cout << resultHeader << "Decrypt " << rv << " "
	      << groupIdx << ":"
	      << json_integer_value(tcId) << " "
	      << json_string_value(comment) << std::endl;

    // If this is a success case, let's encrypt and see if we get the same result

    if (rv == CKR_OK) {
      P11_ASSERT(pFunctionList->C_EncryptInit(session, &mechanism, keyHandle));
      scratchSize = sizeof(scratch);
      rv = pFunctionList->C_Encrypt(session, msg, msgSize, scratch, &scratchSize);

      if (rv == CKR_OK) {
	// Check ciphertext
	if (memcmp(ct, scratch, scratchSize) == 0) {
	  resultHeader = "\e[92m[SUCCESS]\e[0m         ";
	  result.passes++;
	} else {
	  printArr(ct, ctSize);
	  printf("\n");
	  printArr(scratch, scratchSize);
	  printf("\n");
	  resultHeader = "\e[91m[FAILED]\e[0m Bad CT   ";
	  result.failures++;
	}
      } else {
	resultHeader = "\e[91m[FAILED]\e[0m Bad CKR  ";
	result.failures++;
      }

      std::cout << resultHeader << "Encrypt " << rv << " "
		<< groupIdx << ":"
		<< json_integer_value(tcId) << " "
		<< json_string_value(comment) << std::endl;
    }

    json_decref(tcId);
    json_decref(comment);
    json_decref(msgHex);
    json_decref(ctHex);
    json_decref(ivHex);
    json_decref(keyHex);
    free(msg);
    free(ct);
    free(iv);
    
  }
}

groupFunction aesCbcPadRunGroup = &runAesCbcPadGroup;
