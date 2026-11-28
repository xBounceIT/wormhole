#include "../api_darwin.m"
#include <assert.h>

@interface WHFakeBoard : NSObject
@property NSInteger count;
@property BOOL badPrepare;
@property BOOL throwPrepare;
@property BOOL throwWrite;
@property BOOL failWrite;
@property BOOL loseOnCount;
@property BOOL loseOnErase;
@property BOOL throwClose;
@property BOOL secretWritten;
@property BOOL concealed;
@property BOOL transient;
@property BOOL loseAfterText;
@property BOOL throwAfterText;
@property NSUInteger writes;
@end
@implementation WHFakeBoard
- (NSInteger)prepareForNewContentsWithOptions:(NSPasteboardContentsOptions)options {
    assert(options == NSPasteboardContentsCurrentHostOnly);
    if (self.throwPrepare) [NSException raise:@"fixture" format:@"private diagnostics"];
    if (self.badPrepare) return -1;
    return ++_count;
}
- (BOOL)setData:(NSData *)data forType:(NSPasteboardType)type {
    self.writes++;
    if (self.throwWrite) [NSException raise:@"fixture" format:@"private diagnostics"];
    if (self.failWrite) return NO;
    if ([type isEqualToString:@"org.nspasteboard.ConcealedType"]) self.concealed = YES;
    if ([type isEqualToString:@"org.nspasteboard.TransientType"]) self.transient = YES;
    if ([type isEqualToString:NSPasteboardTypeString]) {
        if (data.length) assert(self.concealed && self.transient);
        if (data.length == 0 && self.loseOnErase) {self.count++; return NO;}
        self.secretWritten = data.length > 0;
        if (data.length && self.loseAfterText) self.count++;
        if (data.length && self.throwAfterText) [NSException raise:@"fixture" format:@"private diagnostics"];
    }
    return YES;
}
- (NSInteger)changeCount {if (self.loseOnCount) self.count++; return self.count;}
- (void)releaseGlobally {if (self.throwClose) [NSException raise:@"fixture" format:@"private diagnostics"];}
@end

static WHClipboard *fake(WHFakeBoard **board) {
    WHClipboard *handle = calloc(1, sizeof(*handle));
    *board = [WHFakeBoard new];
    handle->board = (NSPasteboard *)*board;
    handle->owned = -1;
    handle->isolated = 1;
    return handle;
}
int main(void) {
    @autoreleasepool {
        const unsigned char value[] = "synthetic clipboard \xF0\x9F\x98\x80";
        uint64_t ticket = 99;
        assert(wh_clipboard_write(NULL,value,sizeof(value)-1,&ticket) == 1 && ticket == 0);
        assert(wh_clipboard_erase(NULL,1) == 1);
        assert(wh_clipboard_close(NULL) == 0);
        WHClipboard *native = wh_clipboard_create(1);
        assert(native && native->isolated && ![native->board.name isEqualToString:NSPasteboardNameGeneral]);
        assert(wh_clipboard_write(native,NULL,1,&ticket) == 1);
        assert(wh_clipboard_write(native,value,0,&ticket) == 1);
        assert(wh_clipboard_write(native,value,16385,&ticket) == 1);
        assert(wh_clipboard_write(native,value,sizeof(value)-1,NULL) == 1);
        assert(wh_clipboard_write(native,value,sizeof(value)-1,&ticket) == 0 && ticket > 0);
        NSData *expected = [NSData dataWithBytes:value length:sizeof(value)-1];
        assert([[native->board dataForType:NSPasteboardTypeString] isEqualToData:expected]);
        assert([native->board.types containsObject:@"org.nspasteboard.ConcealedType"]);
        assert([native->board.types containsObject:@"org.nspasteboard.TransientType"]);
        assert(wh_clipboard_erase(native,ticket+1) == 0);
        assert([[native->board dataForType:NSPasteboardTypeString] isEqualToData:expected]);
        assert(wh_clipboard_erase(native,ticket) == 0);
        assert([native->board dataForType:NSPasteboardTypeString].length == 0);
        assert(wh_clipboard_write(native,value,sizeof(value)-1,&ticket) == 0);
        [native->board clearContents];
        assert([native->board setString:@"newer external content" forType:NSPasteboardTypeString]);
        assert(wh_clipboard_erase(native,ticket) == 0);
        assert([[native->board stringForType:NSPasteboardTypeString] isEqualToString:@"newer external content"]);
        assert(wh_clipboard_close(native) == 0);
        for (int mode = 0; mode < 10; mode++) {
            WHFakeBoard *board;
            WHClipboard *handle = fake(&board);
            board.badPrepare = mode == 1;
            board.throwPrepare = mode == 2;
            board.throwWrite = mode == 3;
            board.failWrite = mode == 4;
            board.loseOnCount = mode == 5;
            board.loseAfterText = mode == 8;
            board.throwAfterText = mode == 9;
            int result = wh_clipboard_write(handle,value,sizeof(value)-1,&ticket);
            assert(result == ((mode >= 1 && mode <= 5) || mode >= 8 ? 1 : 0));
            if (mode == 0) {
                assert(board.secretWritten && board.writes == 3);
                assert(wh_clipboard_erase(handle,ticket) == 0 && !board.secretWritten);
            }
            if (mode == 6) {
                board.loseOnErase = YES;
                assert(wh_clipboard_erase(handle,ticket) == 0 && board.secretWritten);
            }
            if (mode == 7) {
                board.throwWrite = YES;
                assert(wh_clipboard_erase(handle,ticket) == 1);
                board.throwClose = YES;
            }
            if (mode == 8) {
                assert(handle->owned == 1 && ticket == 2 && board.count == 2);
                NSUInteger writes = board.writes;
                assert(wh_clipboard_erase(handle,ticket) == 0 && board.writes == writes);
            }
            if (mode == 9) assert(wh_clipboard_erase(handle,ticket) == 0 && !board.secretWritten);
            assert(wh_clipboard_close(handle) == (mode == 7 ? 1 : 0));
        }
    }
    return 0;
}
