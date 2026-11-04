// Standalone non-macOS builds are useful for native adapter development.
// Production Windows/Linux retain their existing native desktop adapters.
#include "clipboard.h"
int64_t wh_clipboard_serial(void) { return 0; }
unsigned char* wh_clipboard_read(size_t* length) { *length = 0; return NULL; }
int wh_clipboard_write(const unsigned char* data, size_t length) { (void)data; (void)length; return 0; }
