// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "common.h"

#include <unistd.h>
#include <map>

using std::string;

#define JSON_ASSERT(x, error) do { \
  if ((x) == NULL) {		   \
    fprintf(stderr, "error: on line %d: %s\n", error.line, error.text); \
    return -1;								\
  }									\
  } while (0)

extern groupFunction rsaSigRunGroup;
extern groupFunction dsaRunGroup;
extern groupFunction ecdsaRunGroup;
extern groupFunction aesCbcPadRunGroup;
extern groupFunction aesGcmRunGroup;
extern groupFunction rsaPssRunGroup;

size_t parseHex(const char* hex, CK_BYTE_PTR* result) {
  char* tmpHex = NULL;
  size_t len = strlen(hex);
  if (len % 2) {
    tmpHex = reinterpret_cast<char*>(malloc(len + 2));    
    tmpHex[0] = '0';
    memcpy(tmpHex + 1, hex, len);
    tmpHex[len+1] = '\0';
    hex = tmpHex;
    len = len + 1;
  }

  *result = reinterpret_cast<CK_BYTE_PTR>(malloc(len / 2));
  for (size_t idx = 0; idx < (len / 2); ++idx) {
    sscanf(hex, "%2hhx", (*result + idx));
    hex += 2;    
  }
  if (tmpHex) {
    free(tmpHex);
  }
  return len / 2;
}

void printTemplate(CK_ATTRIBUTE_PTR val, size_t len) {
  char name[33] = { 0 };
  char value[65] = { 0 };
  for (int x = 0; x < len; x++) {
    int valSet = 1;
    CK_ATTRIBUTE attr = val[x];
    // Handle a few which we know about
    switch(attr.type) {
      CASE_ATTR_ULONG(CKA_CLASS, attr);
      CASE_ATTR_BOOL(CKA_TOKEN, attr);
      CASE_ATTR_ARR(CKA_VALUE, attr);
      CASE_ATTR_ULONG(CKA_KEY_TYPE, attr);
      CASE_ATTR_BOOL(CKA_SENSITIVE, attr);
      CASE_ATTR_BOOL(CKA_ENCRYPT, attr);
      CASE_ATTR_BOOL(CKA_DECRYPT, attr);
      CASE_ATTR_BOOL(CKA_SIGN, attr);
      CASE_ATTR_BOOL(CKA_VERIFY, attr);
      CASE_ATTR_BOOL(CKA_EXTRACTABLE, attr);
      CASE_ATTR_BOOL(CKA_LOCAL, attr);
      CASE_ATTR_BOOL(CKA_NEVER_EXTRACTABLE, attr);
      CASE_ATTR_BOOL(CKA_ALWAYS_SENSITIVE, attr);
      CASE_ATTR_BOOL(CKA_DERIVE, attr);
      CASE_ATTR_ULONG(CKA_KEY_GEN_MECHANISM, attr);
      CASE_ATTR_ARR(CKA_MODULUS, attr);
      CASE_ATTR_ARR(CKA_PUBLIC_EXPONENT, attr);
      CASE_ATTR_ARR(CKA_PRIVATE_EXPONENT, attr);
      CASE_ATTR_ARR(CKA_PRIME_1, attr);
      CASE_ATTR_ARR(CKA_PRIME_2, attr);
      CASE_ATTR_ARR(CKA_EXPONENT_1, attr);
      CASE_ATTR_ARR(CKA_EXPONENT_2, attr);
      CASE_ATTR_ARR(CKA_COEFFICIENT, attr);
      CASE_ATTR_ARR(CKA_PRIME, attr);
      CASE_ATTR_ARR(CKA_SUBPRIME, attr);
      CASE_ATTR_ARR(CKA_BASE, attr);
      CASE_ATTR_ARR(CKA_EC_PARAMS, attr);
      CASE_ATTR_ARR(CKA_EC_POINT, attr);
    default:
      strncpy(name, "UNKNOWN", 16);
      strncpy(value, "UNKNOWN", 64);
      valSet = 0;
    }
    printf("%2d: %32s (0x%016lx) = ", x, name, attr.type);
    if (valSet) {
      printf("%s", value);
    } else {
      printArr((CK_BYTE_PTR) attr.pValue, attr.ulValueLen);
    } // */
    printf("\n");
  }
}

CK_OBJECT_HANDLE importSymmetricCryptoKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
					  CK_ULONG keyType,
					  const char* keyHex) {
  unsigned char* key;
  size_t keyLen = parseHex(keyHex, &key);
  assert(keyLen);

  CK_ATTRIBUTE import[] = {
    {CKA_VALUE, key, keyLen},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    ATTR_LOCAL_CONST(CKA_CLASS, CKO_SECRET_KEY, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_DECRYPT, CK_TRUE, CK_BBOOL)
  };
  //  printTemplate(import, sizeofTemplate(import));

  CK_OBJECT_HANDLE result;
  P11_ASSERT(pFunctionList->C_CreateObject(session, import, sizeofTemplate(import), &result));

  free(key);
  return result;
}

CK_OBJECT_HANDLE importEcKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
			     const char* derHex) {
  // SEQUENCE: SubjectPublicKeyInfo  
  //   SEQUENCE: AlgorithmIdentifier
  //     OID
  //     PARAMETERS
  //   BIT STRING (POINT)
  unsigned char* der;
  size_t derLen = parseHex(derHex, &der);
  assert(derLen);
  unsigned char* tmpDer = der;

  // SubjectPublicKeyInfo
  assert(*tmpDer == 0x30);
  tmpDer++; derLen--;

  assert(*tmpDer <= 127 && *tmpDer == derLen - 1);
  tmpDer++; derLen--;

  // AlgorithmIdentifier
  assert(*tmpDer == 0x30);
  tmpDer++; derLen--;

  size_t algInfoLen = *tmpDer;
  assert(algInfoLen <= 127 && algInfoLen < derLen - 2);
  tmpDer++; derLen--;

  assert(*tmpDer == 0x06);
  tmpDer++; derLen--;

  size_t tmpLen = *tmpDer;
  assert(tmpLen <= 127 && tmpLen < algInfoLen - 2);
  tmpDer++; derLen--;
  CK_BYTE_PTR ecParams = tmpDer + tmpLen;
  CK_ULONG ecParamLen = algInfoLen - tmpLen - 2;

  tmpDer = ecParams + ecParamLen; derLen -= algInfoLen - 2;
  tmpDer += 2; derLen -= 2;

  CK_BYTE_PTR ecPoint = tmpDer + 1;
  CK_ULONG ecPointLen = derLen - 1;

  CK_ATTRIBUTE import[] = {
    {CKA_EC_PARAMS, ecParams, ecParamLen},
    {CKA_EC_POINT, ecPoint, ecPointLen},
    ATTR_LOCAL_CONST(CKA_CLASS, CKO_PUBLIC_KEY, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_KEY_TYPE, CKK_EC, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_VERIFY, CK_TRUE, CK_BBOOL)
  };
  printTemplate(import, sizeofTemplate(import));
  
  CK_OBJECT_HANDLE result;
  P11_ASSERT(pFunctionList->C_CreateObject(session, import, sizeofTemplate(import), &result));


  //  free(ecPoint);
  free(der);
  return result;
}

CK_OBJECT_HANDLE importRsaKey(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE session,
			      const char* expHex, const char* modHex) {
  CK_BYTE_PTR exp = NULL, mod = NULL, tmpExp = NULL, tmpMod = NULL;
  size_t expLen, modLen;
  CK_OBJECT_HANDLE result = -1;
  expLen = parseHex(expHex, &exp);
  tmpExp = exp;
  modLen = parseHex(modHex, &mod);
  tmpMod = mod;

  if (exp[0] == 0) {
    tmpExp++;
    expLen--;
  }
  if (mod[0] == 0) {
    tmpMod++;
    modLen--;
  }
  CK_ATTRIBUTE import[] = {
    {CKA_PUBLIC_EXPONENT, tmpExp, expLen},
    {CKA_MODULUS, tmpMod, modLen},
    ATTR_LOCAL_CONST(CKA_CLASS, CKO_PUBLIC_KEY, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_KEY_TYPE, CKK_RSA, CK_ULONG),
    ATTR_LOCAL_CONST(CKA_TOKEN, CK_FALSE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_ENCRYPT, CK_TRUE, CK_BBOOL),
    ATTR_LOCAL_CONST(CKA_VERIFY, CK_TRUE, CK_BBOOL)
  };
  printTemplate(import, sizeofTemplate(import));
  P11_ASSERT(pFunctionList->C_CreateObject(session, import, sizeofTemplate(import), &result));

  free(exp);
  free(mod);

  return result;
}

size_t parseAsn1DsaSig(const unsigned char* der, size_t inLen, unsigned char** sig) {
  size_t rLen, sLen, partLen, sigLen;
  const unsigned char* r;
  const unsigned char* s;

  *sig = NULL;

  if (*der != 0x30) { // SEQUENCE
    return 0;
  }
  der++; inLen--;

  if (*der > 127 || *der != inLen - 1) {
    return 0;
  }
  der++; inLen--;

  if (*der != 0x02) { // INTEGER
    return 0;
  }
  der++; inLen--;

  rLen = *der;
  if (rLen > 127 || rLen > inLen - 1) {
    return 0;
  }
  der++; inLen--;

  r = der;
  if (*r > 127) { // Leading bit must be zero
    return 0;
  }
  der += rLen; inLen -= rLen;

  if (*der != 0x02) { // INTEGER
    return 0;
  }
  der++; inLen--;

  sLen = *der;
  if (sLen > 127 || rLen != inLen - 1) {
    return 0;
  }
  der++; inLen--;

  s = der;
  if (*s > 127) { // Leading bit must be zero
    return 0;
  }

  if (*r == 0) {
    r++;
    rLen--;
  }
  if (*s == 0) {
    s++;
    sLen--;
  }

  partLen = std::max(rLen, sLen);
  
  sigLen = partLen * 2;
  *sig = reinterpret_cast<CK_BYTE_PTR>(malloc(sigLen));
  memset(*sig, 0, sigLen);
  memcpy(*sig + partLen - rLen, r, rLen);
  memcpy(*sig + sigLen - sLen, s, sLen);

  return sigLen;
}

int main(int argc, char** argv)
{
  json_t *root;
  json_t* testGroups;
  size_t testGroupCount;
  json_error_t error;
  char* dlErrorStr;
  void* p11Lib;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_FUNCTION_LIST_PTR pFunctionList;
  CK_SESSION_HANDLE session;
  CK_SLOT_ID slotnum = 0;
  CK_RV rv;
  const char* libName = "";
  char* pin = NULL;
  int opt;
  std::map<string, const char*> ignoredFlags;

  while ((opt = getopt(argc, argv, "l:s:p:i:")) != -1) {
    switch (opt) {
    case 'l':
      libName = optarg;
      break;
    case 's':
      slotnum = atol(optarg);
      break;
    case 'p':
      pin = optarg;
      break;
    case 'i':
      ignoredFlags[optarg] = optarg;
      break;
    default:
      fprintf(stderr, "Usage: %s -l libraryPath -s slotNum -p PIN <-i ignoredFlag1> <-i ignoredFlag2> <testVectors...>\n", argv[0]);
      exit(-1);
    }
  }

  if (optind >= argc) {
      fprintf(stderr, "Usage: %s -l libraryPath -s slotNum -p PIN <-i ignoredFlag1> <-i ignoredFlag2> <testVectors...>\n", argv[0]);
      return -1;
  }

  std::map<string, groupFunction> functions;
  functions["RSASig"] = rsaSigRunGroup;
  functions["DSA"] = dsaRunGroup;
  functions["ECDSA"] = ecdsaRunGroup;
  functions["AES-CBC-PKCS5"] = aesCbcPadRunGroup;
  functions["AES-GCM"] = aesGcmRunGroup;
  functions["RSASSA-PSS"] = rsaPssRunGroup;

  p11Lib = dlopen(libName, RTLD_NOW);
  if (!p11Lib) {
    fprintf(stderr, "%s\n", dlerror());
    exit(-1);
  }
  dlerror();    /* Clear any existing error */

  C_GetFunctionList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(p11Lib, "C_GetFunctionList"));
  dlErrorStr = dlerror();

  if (dlErrorStr) {
    std::cerr << "dlerror: " << dlErrorStr << std::endl;
  }

  P11_ASSERT((C_GetFunctionList)(&pFunctionList));
  P11_ASSERT(pFunctionList->C_Initialize(NULL));
  P11_ASSERT(pFunctionList->C_OpenSession(
					  slotnum,
					  CKF_SERIAL_SESSION | CKF_RW_SESSION,
					  NULL, NULL,
					  &session));
  P11_ASSERT(pFunctionList->C_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(pin), strlen(pin)));

  GroupResult summary = {0};

  for (int fileIdx = optind; fileIdx < argc; ++fileIdx) {
    const char* fileName = argv[fileIdx];
    std::cerr << "Loading: " << fileName << std::endl;
    FILE* jsonFile = fopen(fileName, "r");

    if (!jsonFile) {
      std::cerr << "File didn't open!\n" << std::endl;
      return -1;
    }

    root = json_loadf(jsonFile, 0, &error);
    fclose(jsonFile);
    JSON_ASSERT(root, error);
    assert(json_is_object(root));
    groupFunction fnc;
    {
      json_t* tmp = json_object_get(root, "algorithm");
      assert(tmp);
      assert(json_is_string(tmp));
      fnc = functions[json_string_value(tmp)];
      if (!fnc) {
	std::cerr << "No support for " << json_string_value(tmp) << std::endl;
	json_decref(tmp);
	continue;
      }
      json_decref(tmp);
    }
    testGroups = json_object_get(root, "testGroups");
    assert(testGroups);
    assert(json_is_array(testGroups));
    testGroupCount = json_array_size(testGroups);

    for (size_t currGroup = 0; currGroup < testGroupCount; ++currGroup) {
      json_t* group = json_array_get(testGroups, currGroup);
      assert(group);
      GroupResult result = (*fnc)(pFunctionList, slotnum, session, currGroup, group, ignoredFlags);
      //    json_decref(group);
      if (result.hardFailure) {
	std::cerr << "Hard failure in group " << currGroup << std::endl;
      }
      summary.totalTests += result.totalTests;
      summary.failures += result.failures;
      summary.passes += result.passes;
    }
  }
  const char* resultHeader;
  if (summary.failures) {
    resultHeader = "\e[91m[FAILED]\e[0m  ";
  } else {
    resultHeader = "\e[92m[SUCCESS]\e[0m ";
  }
  std::cout << resultHeader << "Failed " << summary.failures << " out of " << summary.totalTests << std::endl;
  return summary.failures;
}
