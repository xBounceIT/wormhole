#ifndef WORMHOLE_RDP_CLIPBOARD_H
#define WORMHOLE_RDP_CLIPBOARD_H
#include <stdint.h>
#include <stddef.h>
int64_t wh_clipboard_serial(void);
unsigned char* wh_clipboard_read(size_t* length);
int wh_clipboard_write(const unsigned char* data, size_t length);
#endif
