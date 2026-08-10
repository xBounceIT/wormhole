//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef wh_string(const char *value) {
    return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef wh_query(const char *account) {
    CFStringRef service = wh_string("Wormhole");
    CFStringRef accountValue = wh_string(account);
    if (service == NULL || accountValue == NULL) {
        if (service != NULL) CFRelease(service);
        if (accountValue != NULL) CFRelease(accountValue);
        return NULL;
    }
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service);
    CFDictionarySetValue(query, kSecAttrAccount, accountValue);
    CFRelease(service);
    CFRelease(accountValue);
    return query;
}

static int wh_store(const char *account, const unsigned char *value, size_t valueLength) {
    CFMutableDictionaryRef item = wh_query(account);
    if (item == NULL) return errSecParam;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)valueLength);
    if (data == NULL) { CFRelease(item); return errSecAllocate; }
    CFDictionarySetValue(item, kSecValueData, data);
    CFDictionarySetValue(item, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    OSStatus status = SecItemAdd(item, NULL);
    CFRelease(data);
    CFRelease(item);
    if (status != errSecDuplicateItem) return (int)status;

    CFMutableDictionaryRef query = wh_query(account);
    if (query == NULL) return errSecParam;
    CFDataRef replacement = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)valueLength);
    if (replacement == NULL) { CFRelease(query); return errSecAllocate; }
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attributes, kSecValueData, replacement);
    status = SecItemUpdate(query, attributes);
    CFRelease(attributes);
    CFRelease(replacement);
    CFRelease(query);
    return (int)status;
}

static int wh_load(const char *account, unsigned char **value, size_t *valueLength) {
    *value = NULL;
    *valueLength = 0;
    CFMutableDictionaryRef query = wh_query(account);
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess) return (int)status;
    CFDataRef data = (CFDataRef)result;
    CFIndex length = CFDataGetLength(data);
    unsigned char *copy = malloc(length > 0 ? (size_t)length : 1);
    if (copy == NULL) { CFRelease(data); return errSecAllocate; }
    if (length > 0) memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
    CFRelease(data);
    *value = copy;
    *valueLength = (size_t)length;
    return errSecSuccess;
}

static int wh_delete(const char *account) {
    CFMutableDictionaryRef query = wh_query(account);
    if (query == NULL) return errSecParam;
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    return (int)status;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func prepareCredentialSecretStorage(id string) (string, string, error) {
	reference, err := newCredentialSecretReference(id)
	return reference, darwinKeychainEncoding, err
}

func storeCredentialSecret(id, reference, value string) (string, string, error) {
	var err error
	if reference == "" {
		reference, err = newCredentialSecretReference(id)
	}
	if err != nil {
		return "", "", err
	}
	account, err := credentialSecretAccount(id, reference)
	if err != nil {
		return "", "", err
	}
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(accountValue))
	password := []byte(value)
	passwordValue := C.CBytes(password)
	defer C.free(passwordValue)
	if status := C.wh_store(accountValue, (*C.uchar)(passwordValue), C.size_t(len(password))); status != 0 {
		return "", "", errors.New("the macOS Keychain is unavailable")
	}
	return reference, darwinKeychainEncoding, nil
}

func unprotectPlatformCredentialSecret(id, encoded, encoding string) ([]byte, error) {
	if encoding != darwinKeychainEncoding {
		return nil, errUnsupportedSecretEncoding
	}
	account, err := credentialSecretAccount(id, encoded)
	if err != nil {
		return nil, errors.New("stored credential reference is invalid")
	}
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(accountValue))
	var passwordValue *C.uchar
	var passwordLength C.size_t
	if status := C.wh_load(accountValue, &passwordValue, &passwordLength); status != 0 {
		return nil, errors.New("the macOS Keychain is unavailable")
	}
	defer C.free(unsafe.Pointer(passwordValue))
	return C.GoBytes(unsafe.Pointer(passwordValue), C.int(passwordLength)), nil
}

func deleteStoredCredentialSecret(id, encoded, encoding string) error {
	if encoding != darwinKeychainEncoding {
		return nil
	}
	account, err := credentialSecretAccount(id, encoded)
	if err != nil {
		return err
	}
	accountValue := C.CString(account)
	defer C.free(unsafe.Pointer(accountValue))
	if status := C.wh_delete(accountValue); status != 0 && status != C.errSecItemNotFound {
		return errors.New("the macOS Keychain is unavailable")
	}
	return nil
}
