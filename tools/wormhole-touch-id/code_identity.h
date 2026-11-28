#pragma once

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Security/CSCommon.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define WH_TOUCH_ID_IDENTIFIER CFSTR("com.xbounceit.wormhole.vault-touch-id")

static inline CFStringRef WHDeveloperTeam(SecCodeRef running, SecStaticCodeRef onDisk, CFStringRef expectedIdentifier) {
    SecStaticCodeRef code = onDisk;
    if (running != NULL) {
        if (SecCodeCopyStaticCode(running, kSecCSDefaultFlags, &code) != errSecSuccess) return NULL;
    } else if (code != NULL) {
        CFRetain(code);
    } else {
        return NULL;
    }

    SecRequirementRef requirement = NULL;
    CFDictionaryRef signing = NULL;
    CFStringRef team = NULL;
    OSStatus status = SecRequirementCreateWithString(
        CFSTR("anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),
        kSecCSDefaultFlags, &requirement);
    if (status != errSecSuccess) goto done;
    if (running != NULL) {
        status = SecCodeCheckValidity(running, kSecCSDefaultFlags, requirement);
    } else {
        status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, requirement);
    }
    if (status != errSecSuccess || SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing) != errSecSuccess) goto done;
    CFStringRef identifier = CFDictionaryGetValue(signing, kSecCodeInfoIdentifier);
    if (expectedIdentifier != NULL && (identifier == NULL || !CFEqual(identifier, expectedIdentifier))) goto done;
    CFNumberRef flags = CFDictionaryGetValue(signing, kSecCodeInfoFlags);
    uint32_t codeFlags = 0;
    if (flags == NULL || !CFNumberGetValue(flags, kCFNumberSInt32Type, &codeFlags) || (codeFlags & kSecCodeSignatureRuntime) == 0) goto done;
    CFDictionaryRef entitlements = CFDictionaryGetValue(signing, kSecCodeInfoEntitlementsDict);
    if (entitlements != NULL && CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.get-task-allow")) == kCFBooleanTrue) goto done;
    CFStringRef value = CFDictionaryGetValue(signing, kSecCodeInfoTeamIdentifier);
    if (value != NULL && CFStringGetLength(value) == 10) team = CFRetain(value);

done:
    if (signing != NULL) CFRelease(signing);
    if (requirement != NULL) CFRelease(requirement);
    CFRelease(code);
    return team;
}

static inline CFStringRef WHOwnDeveloperTeam(CFStringRef identifier) {
    SecCodeRef code = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess) return NULL;
    CFStringRef team = WHDeveloperTeam(code, NULL, identifier);
    CFRelease(code);
    return team;
}

static inline Boolean WHIsDeveloperProcess(pid_t pid, CFStringRef identifier, CFStringRef expectedTeam) {
    if (pid <= 1 || expectedTeam == NULL) return false;
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (number == NULL) return false;
    const void *key = kSecGuestAttributePid;
    const void *value = number;
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, &key, &value, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(number);
    if (attributes == NULL) return false;
    SecCodeRef process = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &process);
    CFRelease(attributes);
    if (status != errSecSuccess) return false;
    CFStringRef team = WHDeveloperTeam(process, NULL, identifier);
    CFRelease(process);
    Boolean equal = team != NULL && CFEqual(team, expectedTeam);
    if (team != NULL) CFRelease(team);
    return equal;
}
