//go:build darwin && cgo

#import <AppKit/AppKit.h>
#include <stdlib.h>
#include <string.h>
#include "api_darwin.h"

typedef struct {
    NSPasteboard *board;
    NSInteger owned;
    int isolated;
} WHClipboard;

void *wh_clipboard_create(int isolated) {
    @autoreleasepool {
        WHClipboard *handle = calloc(1, sizeof(*handle));
        if (!handle) return NULL;
        @try {
            handle->board = [(isolated ? [NSPasteboard pasteboardWithUniqueName] : [NSPasteboard generalPasteboard]) retain];
            handle->isolated = isolated;
            handle->owned = -1;
            if (!handle->board) { free(handle); return NULL; }
            return handle;
        } @catch (NSException *exception) {
            (void)exception;
            free(handle);
            return NULL;
        }
    }
}

int wh_clipboard_write(void *opaque, const unsigned char *value, size_t length, uint64_t *ticket) {
    if (ticket) *ticket = 0;
    if (!opaque || !value || !ticket || length == 0 || length > 16384) return 1;
    WHClipboard *handle = opaque;
    @autoreleasepool {
        NSMutableData *text = nil;
        @try {
            // The preparation count identifies OUR claim, never a later writer.
            // Markers are published before text, with cross-device copying off.
            NSInteger count = [handle->board prepareForNewContentsWithOptions:NSPasteboardContentsCurrentHostOnly];
            if (count < 0) return 1;
            handle->owned = count;
            *ticket = (uint64_t)count + 1;
            for (NSString *type in @[@"org.nspasteboard.ConcealedType", @"org.nspasteboard.TransientType"]) {
                if (![handle->board setData:[NSData data] forType:type]) return 1;
            }
            if ([handle->board changeCount] != count) return 1;
            text = [NSMutableData dataWithBytes:value length:length];
            if (!text || ![handle->board setData:text forType:NSPasteboardTypeString]) return 1;
            return [handle->board changeCount] == count ? 0 : 1;
        } @catch (NSException *exception) {
            (void)exception;
            // Communication exceptions may follow publication; keep the ticket
            // so the Go owner retries cleanup. Never expose native diagnostics.
            return 1;
        } @finally {
            if (text.length) explicit_bzero(text.mutableBytes, text.length);
        }
    }
}

int wh_clipboard_erase(void *opaque, uint64_t ticket) {
    if (!opaque) return 1;
    WHClipboard *handle = opaque;
    @autoreleasepool {
        @try {
            if (!ticket || handle->owned < 0 || ticket != (uint64_t)handle->owned + 1 || [handle->board changeCount] != handle->owned) return 0;
            // Do NOT clearContents: that would take ownership from a newer
            // writer in the check/clear gap. setData refuses a changed owner.
            // UTF-8 text is the only plaintext representation we publish.
            [handle->board setData:[NSData data] forType:NSPasteboardTypeString];
            return 0;
        } @catch (NSException *exception) {
            (void)exception;
            return 1;
        }
    }
}

int wh_clipboard_close(void *opaque) {
    if (!opaque) return 0;
    WHClipboard *handle = opaque;
    int result = 0;
    @autoreleasepool {
        @try {
            if (handle->isolated) [handle->board releaseGlobally];
        } @catch (NSException *exception) {
            (void)exception;
            result = 1;
        }
        @finally {
            [handle->board release];
            free(handle);
        }
    }
    return result;
}
