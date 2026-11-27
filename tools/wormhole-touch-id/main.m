#define __STDC_WANT_LIB_EXT1__ 1
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <Security/SecTask.h>
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include "code_identity.h"

enum { protocolVersion = 1, probe = 1, enroll = 2, openFactor = 3, removeFactor = 4 };
enum { ok = 0, unavailable = 1, canceled = 2 };
enum { headerSize = 2, idSize = 36, factorSize = 32 };

static NSString *ExecutablePath(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof(path)) <= 0) return nil;
    return [[NSString stringWithUTF8String:path] stringByResolvingSymlinksInPath];
}

static BOOL TrustedParent(pid_t backend, CFStringRef team) {
    if (getppid() != backend || !WHIsDeveloperProcess(backend, NULL, team)) return NO;
    NSURL *helper = NSBundle.mainBundle.bundleURL;
    NSURL *helpers = helper.URLByDeletingLastPathComponent;
    NSURL *contents = helpers.URLByDeletingLastPathComponent;
    if (![helpers.lastPathComponent isEqualToString:@"Helpers"] || ![contents.lastPathComponent isEqualToString:@"Contents"] ||
        ![contents.URLByDeletingLastPathComponent.pathExtension isEqualToString:@"app"]) return NO;
    NSString *resources = [[contents URLByAppendingPathComponent:@"Resources"] path].stringByResolvingSymlinksInPath;
    NSString *backendPath = ExecutablePath(backend);
    if (![backendPath.stringByDeletingLastPathComponent isEqualToString:resources] ||
        ![backendPath.lastPathComponent isEqualToString:@"wormhole-backend-universal"]) return NO;
    struct proc_bsdinfo info;
    if (proc_pidinfo(backend, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != (int)sizeof(info)) return NO;
    pid_t app = (pid_t)info.pbi_ppid;
    NSString *binDir = [[contents URLByAppendingPathComponent:@"MacOS"] path].stringByResolvingSymlinksInPath;
    return [ExecutablePath(app).stringByDeletingLastPathComponent isEqualToString:binDir] &&
        WHIsDeveloperProcess(app, CFSTR("com.xbounceit.wormhole"), team) && getppid() == backend;
}

static BOOL IsPipe(int fd) {
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISFIFO(info.st_mode);
}

static ssize_t ReadRequest(uint8_t *buffer, size_t capacity) {
    size_t length = 0;
    while (length < capacity) {
        ssize_t count = read(STDIN_FILENO, buffer + length, capacity - length);
        if (count == 0) return (ssize_t)length;
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -1;
        length += (size_t)count;
    }
    return -1;
}

static BOOL WriteResponse(const uint8_t *buffer, size_t length) {
    while (length > 0) {
        ssize_t count = write(STDOUT_FILENO, buffer, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        buffer += count;
        length -= (size_t)count;
    }
    return YES;
}

static BOOL IsID(const uint8_t *id) {
    BOOL nonzero = NO;
    for (size_t i = 0; i < idSize; ++i) {
        uint8_t c = id[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return NO;
        } else {
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) return NO;
            nonzero |= c != '0';
        }
    }
    return nonzero;
}

static int PublicStatus(OSStatus status) {
    if (status == errSecSuccess) return ok;
    if (status == errSecUserCanceled) return canceled;
    return unavailable;
}

static OSStatus CopyFactor(NSDictionary *identity, LAContext *context, uint8_t out[factorSize]) {
    NSMutableDictionary *query = [identity mutableCopy];
    query[(__bridge id)kSecUseAuthenticationContext] = context;
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef value = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &value);
    if (status == errSecSuccess) {
        if (value == NULL || CFGetTypeID(value) != CFDataGetTypeID() || CFDataGetLength(value) != factorSize) {
            status = errSecDecode;
        } else {
            CFDataGetBytes(value, CFRangeMake(0, factorSize), out);
        }
    }
    if (value != NULL) CFRelease(value);
    return status;
}

static OSStatus RemoveFactor(NSDictionary *identity) {
    LAContext *context = [[LAContext alloc] init];
    context.interactionNotAllowed = YES;
    NSMutableDictionary *query = [identity mutableCopy];
    query[(__bridge id)kSecUseAuthenticationContext] = context;
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return status == errSecItemNotFound ? errSecSuccess : status;
}

static int RunOperation(uint8_t operation, NSString *group, NSString *account, uint8_t out[factorSize]) {
    LAContext *context = [[LAContext alloc] init];
    NSDictionary *identity = @{
        (__bridge id)kSecUseDataProtectionKeychain: @YES,
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"com.xbounceit.wormhole.vault-touch-id",
        (__bridge id)kSecAttrAccessGroup: group,
        (__bridge id)kSecAttrAccount: account ?: @"",
        (__bridge id)kSecAttrSynchronizable: @NO,
    };
    if (operation == removeFactor) return PublicStatus(RemoveFactor(identity));
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:NULL] ||
        context.biometryType != LABiometryTypeTouchID) return unavailable;
    if (operation == probe) return ok;
    context.localizedFallbackTitle = @"";
    context.touchIDAuthenticationAllowableReuseDuration = 0;
    context.localizedReason = operation == enroll ? @"Set up Touch ID for your Wormhole vault" : @"Unlock your Wormhole vault";
    if (operation == openFactor) return PublicStatus(CopyFactor(identity, context, out));

    SecAccessControlRef control = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlBiometryCurrentSet, NULL);
    if (control == NULL) return unavailable;
    uint8_t random[factorSize];
    OSStatus status = SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random);
    if (status == errSecSuccess) {
        NSMutableDictionary *item = [identity mutableCopy];
        item[(__bridge id)kSecAttrAccessControl] = (__bridge id)control;
        item[(__bridge id)kSecValueData] = [NSData dataWithBytesNoCopy:random length:sizeof(random) freeWhenDone:NO];
        status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }
    memset_s(random, sizeof(random), 0, sizeof(random));
    CFRelease(control);
    if (status == errSecSuccess) {
        status = CopyFactor(identity, context, out);
        if (status != errSecSuccess) RemoveFactor(identity);
    }
    return PublicStatus(status);
}

int main(int argc, char **argv) {
    (void)argv;
    @autoreleasepool {
        if (argc != 1 || !IsPipe(STDIN_FILENO) || !IsPipe(STDOUT_FILENO)) return 1;
        NSString *team = CFBridgingRelease(WHOwnDeveloperTeam(WH_TOUCH_ID_IDENTIFIER));
        pid_t backend = getppid();
        if (team == nil || !TrustedParent(backend, (__bridge CFStringRef)team)) return 1;
        NSString *group = [team stringByAppendingString:@".com.xbounceit.wormhole.vault-touch-id"];
        SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
        if (task == NULL) return 1;
        id applicationID = CFBridgingRelease(SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.application-identifier"), NULL));
        CFRelease(task);
        if (![group isEqual:applicationID]) return 1;

        uint8_t request[headerSize + 2 * idSize + 1];
        ssize_t length = ReadRequest(request, sizeof(request));
        if (length < headerSize || request[0] != protocolVersion) return 1;
        uint8_t operation = request[1];
        NSString *account = nil;
        if (operation == probe) {
            if (length != headerSize) return 1;
        } else {
            if (operation < enroll || operation > removeFactor || length != headerSize + 2 * idSize ||
                !IsID(request + headerSize) || !IsID(request + headerSize + idSize)) return 1;
            NSString *vaultID = [[NSString alloc] initWithBytes:request + headerSize length:idSize encoding:NSASCIIStringEncoding];
            NSString *slotID = [[NSString alloc] initWithBytes:request + headerSize + idSize length:idSize encoding:NSASCIIStringEncoding];
            account = [NSString stringWithFormat:@"%@/%@", vaultID, slotID];
        }
        if (!TrustedParent(backend, (__bridge CFStringRef)team)) return 1;
        uint8_t response[headerSize + factorSize] = {protocolVersion, 0};
        response[1] = (uint8_t)RunOperation(operation, group, account, response + headerSize);
        size_t responseSize = headerSize + (response[1] == ok && (operation == enroll || operation == openFactor) ? factorSize : 0);
        BOOL sent = TrustedParent(backend, (__bridge CFStringRef)team) && WriteResponse(response, responseSize);
        if (!sent && operation == enroll && response[1] == ok) {
            // The pipe may close after creation but before the parent can commit.
            RunOperation(removeFactor, group, account, response + headerSize);
        }
        memset_s(response, sizeof(response), 0, sizeof(response));
        return sent ? 0 : 1;
    }
}
