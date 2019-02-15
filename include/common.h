// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMMON_H
#define COMMON_H 1

// Definitions required by pkcs11.h
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
// End definitions for pkcs11.h

#include "pkcs11.h"

#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <map>
#include <iostream>
#include <jansson.h>

#define P11_ASSERT(x) do { \
  CK_RV rv = (x);	   \
  if (rv != CKR_OK) {	   \
  std::cerr << "Failed call: " << #x << " = " << rv << std::endl; \
  assert(false); \
  } \
  } while(0)

#define json_object_get_string(dst, obj, name) do { \
  dst = json_object_get(obj, name);		    \
  assert(dst);					    \
  assert(json_is_string(dst));			    \
  } while (0)

#define ATTR_LOCAL(type, value) {type, fillAttrParam(alloca(sizeof(value)), &value, sizeof(value)), sizeof(value)}
#define ATTR_ARR(type, size) {type, fillAttrParam(alloca(size), NULL, size), size}
#define ATTR_BOOL(type, value) ATTR_LOCAL_CONST(type, value, CK_BBOOL)
#define ATTR_ULONG(type, value) ATTR_LOCAL_CONST(type, value, CK_ULONG)
#define ATTR_LOCAL_CONST(type, value, dType) {type, fillAttrParamConst(alloca(sizeof(dType)), value, sizeof(dType)), sizeof(dType)}

static inline void* fillAttrParam(void* dst, void* src, size_t size) {
  if (src != NULL) {
    memcpy(dst, src, size);
  } else {
    memset(dst, 0, size);
  }
  return dst;
}

static void printArr(CK_BYTE_PTR arr, size_t len) {
  for (int x = 0; x < len; x++) {
    printf("%02hhX", arr[x]);
  }
}

#define COPY_CONST_VAL(dst, src, type) do { *((type*) dst) = (type) src; } while (0)

static inline void* fillAttrParamConst(void* dst, uint64_t src, size_t size) {
  switch (size) {
  case 1:
    COPY_CONST_VAL(dst, src, uint8_t);
    break;
  case 2:
    COPY_CONST_VAL(dst, src, uint16_t);
    break;
  case 4:
    COPY_CONST_VAL(dst, src, uint32_t);
    break;
  case 8:
    COPY_CONST_VAL(dst, src, uint64_t);
    break;
  default:
    printf("Unknown size: %d\n", size);
    return NULL;
  }
  return dst;
}

#define ATTR(type, value) {type, &value, sizeof(value)}

#define CASE_ATTR_BYTE(cka, attr) \
 case cka: \
 assert(attr.ulValueLen == 1); \
 strncpy(name, #cka, 32); \
 snprintf(value, 65, "0x%02hhX", *(unsigned char*)attr.pValue);	\
 break; \

#define CASE_ATTR_BOOL(cka, attr) \
 case cka: \
 assert(attr.ulValueLen == 1); \
 strncpy(name, #cka, 32); \
 snprintf(value, 65, "%s", (*(unsigned char*)attr.pValue) ? "CK_TRUE" : "CK_FALSE"); \
 break; \

#define CASE_ATTR_ULONG(cka, attr) \
 case cka: \
 assert(attr.ulValueLen == 8); \
 strncpy(name, #cka, 32); \
 snprintf(value, 65, "0x%016lx", *(unsigned long*)attr.pValue);	\
 break; \


#define CASE_ATTR_ARR(cka, attr) \
case cka:			 \
 strncpy(name, #cka, 32); \
 valSet = 0; \
 break;	    \

#define sizeofTemplate(x) (sizeof(x) / sizeof(CK_ATTRIBUTE))

void printTemplate(CK_ATTRIBUTE_PTR, size_t);

size_t parseHex(const char* hex, CK_BYTE_PTR* result);

struct GroupResult_t {
public:
  size_t totalTests;
  size_t failures;
  size_t passes;
  bool hardFailure;
} typedef GroupResult;

CK_OBJECT_HANDLE importRsaKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
			      const char* expHex, const char* modHex);

CK_OBJECT_HANDLE importEcKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
			     const char* keyDerHex);

size_t parseAsn1DsaSig(const unsigned char* der, size_t inLen, unsigned char** sig);

CK_OBJECT_HANDLE importSymmetricCryptoKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
					  CK_ULONG keyType,
					  const char* keyHex);

static inline bool shouldSkip(json_t* testCase, std::map<std::string, const char*>& ignoredFlags) {
  json_t* flags = json_object_get(testCase, "flags");
  assert(flags);
  size_t flagCount = json_array_size(flags);
  for (size_t idx = 0; idx < flagCount; ++idx) {
    json_t* currFlag = json_array_get(flags, idx);
    const char* flag = ignoredFlags[json_string_value(currFlag)];
    json_decref(currFlag);
    if (flag != NULL) {
      json_decref(flags);
      return true;
    }
  }
  json_decref(flags);
  return false;
}

typedef GroupResult (*groupFunction)(CK_FUNCTION_LIST_PTR pFunctionList, CK_SLOT_ID slot, CK_SESSION_HANDLE session, size_t groupIdx, json_t* testGroup, std::map<std::string, const char*>& ignoredFlags);
#endif
