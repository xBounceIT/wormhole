#ifndef WORMHOLE_SECRET_CLIPBOARD_H
#define WORMHOLE_SECRET_CLIPBOARD_H
#include <stddef.h>
#include <stdint.h>
void *wh_clipboard_create(int isolated);
int wh_clipboard_write(void *handle, const unsigned char *value, size_t length, uint64_t *ticket);
int wh_clipboard_erase(void *handle, uint64_t ticket);
int wh_clipboard_close(void *handle);
#endif
