#import <AppKit/AppKit.h>
#include <stdlib.h>
#include "clipboard.h"

int64_t wh_clipboard_serial(void) {
  @autoreleasepool { return [[NSPasteboard generalPasteboard] changeCount]; }
}
unsigned char* wh_clipboard_read(size_t* length) {
  *length = 0;
  @autoreleasepool {
    NSString* text = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];
    if (!text || text.length > 131071) return NULL;
    NSData* encoded = [text dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    if (!encoded || encoded.length > 262142) return NULL;
    unsigned char* result = calloc(encoded.length + 2, 1);
    if (!result) return NULL;
    memcpy(result, encoded.bytes, encoded.length);
    *length = encoded.length + 2;
    return result;
  }
}
int wh_clipboard_write(const unsigned char* data, size_t length) {
  if (!data || length > 262144 || length % 2) return 0;
  @autoreleasepool {
    if (length >= 2 && data[length-1] == 0 && data[length-2] == 0) length -= 2;
    NSString* text = [[NSString alloc] initWithBytes:data length:length encoding:NSUTF16LittleEndianStringEncoding];
    if (!text) return 0;
    NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
    [pasteboard clearContents];
    return [pasteboard setString:text forType:NSPasteboardTypeString] ? 1 : 0;
  }
}
