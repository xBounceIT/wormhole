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

static CFMutableDictionaryRef wh_query(const char *serviceName, const char *account) {
    CFStringRef service = wh_string(serviceName);
    CFStringRef accountValue = wh_string(account);
    if (service == NULL || accountValue == NULL) {
        if (service != NULL) CFRelease(service);
        if (accountValue != NULL) CFRelease(accountValue);
        return NULL;
    }
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query != NULL) {
        CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, accountValue);
    }
    CFRelease(service);
    CFRelease(accountValue);
    return query;
}

static int wh_add(const char *service, const char *account, const unsigned char *value, size_t valueLength, int deviceOnly) {
    CFMutableDictionaryRef item = wh_query(service, account);
    if (item == NULL) return errSecParam;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)valueLength);
    if (data == NULL) { CFRelease(item); return errSecAllocate; }
    CFDictionarySetValue(item, kSecValueData, data);
    if (deviceOnly) CFDictionarySetValue(item, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    OSStatus status = SecItemAdd(item, NULL);
    CFRelease(data);
    CFRelease(item);
    return (int)status;
}

static int wh_store(const char *account, const unsigned char *value, size_t valueLength) {
    int added = wh_add("Wormhole", account, value, valueLength, 1);
    if (added != errSecDuplicateItem) return added;
    CFMutableDictionaryRef query = wh_query("Wormhole", account);
    if (query == NULL) return errSecParam;
    CFDataRef replacement = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)valueLength);
    if (replacement == NULL) { CFRelease(query); return errSecAllocate; }
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attributes, kSecValueData, replacement);
    OSStatus status = SecItemUpdate(query, attributes);
    CFRelease(attributes);
    CFRelease(replacement);
    CFRelease(query);
    return (int)status;
}

static int wh_copy_password(CFTypeRef result, size_t maximum, unsigned char **value, size_t *valueLength) {
    if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) return errSecDecode;
    CFIndex length = CFDataGetLength((CFDataRef)result);
    if (length < 0 || (size_t)length > maximum) return errSecParam;
    unsigned char *copy = malloc(length > 0 ? (size_t)length : 1);
    if (copy == NULL) return errSecAllocate;
    if (length > 0) memcpy(copy, CFDataGetBytePtr((CFDataRef)result), (size_t)length);
    *value = copy;
    *valueLength = (size_t)length;
    return errSecSuccess;
}

static int wh_load(const char *service, const char *account, size_t maximum, unsigned char **value, size_t *valueLength) {
    *value = NULL;
    *valueLength = 0;
    CFMutableDictionaryRef query = wh_query(service, account);
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecSuccess) status = wh_copy_password(result, maximum, value, valueLength);
    if (result != NULL) CFRelease(result);
    return (int)status;
}

static int wh_delete(const char *account) {
    CFMutableDictionaryRef query = wh_query("Wormhole", account);
    if (query == NULL) return errSecParam;
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    return (int)status;
}

// Migration never deletes by an account-wide query. Resolve exactly one native
// item without prompting, then read/delete that reference. MatchLimitAll cannot
// be combined with ReturnData for passwords, so resolution and reading are split.
static int wh_migration_item(const char *service, const char *account, CFTypeRef *item) {
    *item = NULL;
    CFMutableDictionaryRef query = wh_query(service, account);
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess) return (int)status;
    if (result == NULL) return errSecDecode;
    if (CFGetTypeID(result) != CFArrayGetTypeID() || CFArrayGetCount((CFArrayRef)result) != 1) {
        CFRelease(result);
        return errSecDuplicateItem;
    }
    *item = CFRetain(CFArrayGetValueAtIndex((CFArrayRef)result, 0));
    CFRelease(result);
    return errSecSuccess;
}

static CFMutableDictionaryRef wh_migration_query(CFTypeRef item) {
    if (item == NULL) return NULL;
    CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, &item, 1, &kCFTypeArrayCallBacks);
    if (items == NULL) return NULL;
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query != NULL) {
        CFDictionarySetValue(query, kSecMatchItemList, items);
        CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    }
    CFRelease(items);
    return query;
}

static int wh_migration_load(CFTypeRef item, size_t maximum, unsigned char **value, size_t *valueLength) {
    *value = NULL;
    *valueLength = 0;
    CFMutableDictionaryRef query = wh_migration_query(item);
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecSuccess) status = wh_copy_password(result, maximum, value, valueLength);
    if (result != NULL) CFRelease(result);
    return (int)status;
}

static int wh_migration_delete(CFTypeRef item) {
    CFMutableDictionaryRef query = wh_migration_query(item);
    if (query == NULL) return errSecParam;
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    return (int)status;
}

static int wh_delete_protected_key(const char *service, const char *account) {
    CFTypeRef item = NULL;
    int status = wh_migration_item(service, account, &item);
    if (status != errSecSuccess) return status;
    status = wh_migration_delete(item);
    CFRelease(item);
    return status;
}

static void wh_migration_free(unsigned char *value, size_t length) {
    volatile unsigned char *cursor = value;
    while (length-- > 0) *cursor++ = 0;
    free(value);
}
*/
import "C"

import (
	"context"
	"errors"
	"strings"
	"sync"
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
	value, err := readMacKeyringPassword("Wormhole", account, backendMaxTunnelRequestBytes)
	if err != nil {
		return nil, errors.New("the macOS Keychain is unavailable")
	}
	return value, nil
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

// Migration must distinguish a missing item from a locked or unavailable
// Keychain. Keep the legacy reader's existing error contract unchanged.
func openMigrationCredentialStore(ctx context.Context, row legacyInventoryRow, maximum int) (migrationCredentialStore, error) {
	if ctx.Err() != nil || strings.TrimSpace(row.Encoding) != darwinKeychainEncoding || maximum < 1 || maximum > backendMaxTunnelRequestBytes {
		return migrationCredentialStore{}, errUnsupportedSecretEncoding
	}
	account, err := credentialSecretAccount(strings.ToLower(row.ID), row.Reference)
	if err != nil {
		return migrationCredentialStore{}, errVaultMigrationSource
	}
	var selected C.CFTypeRef
	closed := false
	clearSelected := func() {
		if selected != 0 {
			C.CFRelease(selected)
			selected = 0
		}
	}
	store := migrationCredentialStore{Close: sync.OnceFunc(func() { closed = true; clearSelected() })}
	store.Load = func(ctx context.Context) ([]byte, bool, error) {
		if closed || ctx.Err() != nil {
			return nil, false, errVaultMigrationSource
		}
		clearSelected()
		service, name := C.CString("Wormhole"), C.CString(account)
		defer C.free(unsafe.Pointer(service))
		defer C.free(unsafe.Pointer(name))
		status := C.wh_migration_item(service, name, &selected)
		if status == C.errSecItemNotFound {
			return nil, false, nil
		}
		if status != 0 {
			return nil, false, errVaultMigrationSource
		}
		var value *C.uchar
		var length C.size_t
		status = C.wh_migration_load(selected, C.size_t(maximum), &value, &length)
		if value != nil {
			defer C.wh_migration_free(value, length)
		}
		if status != 0 || length > C.size_t(maximum) || ctx.Err() != nil {
			clearSelected()
			return nil, false, errVaultMigrationSource
		}
		return C.GoBytes(unsafe.Pointer(value), C.int(length)), true, nil
	}
	store.Delete = func(ctx context.Context) error {
		if closed || selected == 0 || ctx.Err() != nil {
			return errVaultMigrationSource
		}
		status := C.wh_migration_delete(selected)
		if status != 0 && status != C.errSecItemNotFound {
			return errVaultMigrationSource
		}
		return ctx.Err()
	}
	return store, nil
}

func readMacKeyringPassword(service, account string, maximum int) ([]byte, error) {
	serviceValue, accountValue := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(serviceValue))
	defer C.free(unsafe.Pointer(accountValue))
	var value *C.uchar
	var length C.size_t
	status := C.wh_load(serviceValue, accountValue, C.size_t(maximum), &value, &length)
	if err := macProtectedKeyringError(status); err != nil {
		return nil, err
	}
	defer C.wh_migration_free(value, length)
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

func addMacProtectedKeyringPassword(service, account string, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxMacProtectedKey {
		return errMacProtectedKeyringValue
	}
	serviceValue, accountValue := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(serviceValue))
	defer C.free(unsafe.Pointer(accountValue))
	// File-based Keychain is intentional for the existing keyring namespace.
	// Add without replacing a key that another process has already created.
	return macProtectedKeyringError(C.wh_add(serviceValue, accountValue, (*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)), 0))
}

func macProtectedKeyringError(status C.int) error {
	switch status {
	case C.errSecSuccess:
		return nil
	case C.errSecItemNotFound:
		return errProtectedKeyringNotFound
	default:
		return errCredentialSecretStoreUnavailable
	}
}

func platformProtectedKeyring() protectedKeyringAdapter {
	return protectedKeyringAdapter{
		load: func(service, account string) ([]byte, error) {
			raw, err := readMacKeyringPassword(service, account, maxMacProtectedKey)
			defer clearBytes(raw)
			if err != nil {
				return nil, err
			}
			return decodeMacProtectedKeyringValue(raw)
		},
		store: func(service, account string, value []byte) error {
			raw := encodeMacProtectedKeyringValue(value)
			defer clearBytes(raw)
			return addMacProtectedKeyringPassword(service, account, raw)
		},
		remove: func(service, account string) error {
			serviceValue, accountValue := C.CString(service), C.CString(account)
			defer C.free(unsafe.Pointer(serviceValue))
			defer C.free(unsafe.Pointer(accountValue))
			return macProtectedKeyringError(C.wh_delete_protected_key(serviceValue, accountValue))
		},
	}
}
