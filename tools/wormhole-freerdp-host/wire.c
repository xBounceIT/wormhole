#include "wire.h"
#include <stdlib.h>
#include <string.h>

static int read_u32(FILE* input, uint32_t* result) {
  unsigned char bytes[4];
  if (fread(bytes, 1, 4, input) != 4) return 0;
  *result = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
            ((uint32_t)bytes[2] << 8) | bytes[3];
  return 1;
}

void wh_free_settings(int argc, char** argv) {
  if (!argv) return;
  for (int i = 0; i < argc; ++i) {
    if (argv[i]) {
      volatile char* data = argv[i];
      size_t length = strlen(argv[i]);
      while (length--) *data++ = 0;
      free(argv[i]);
    }
  }
  free(argv);
}

int wh_read_settings(FILE* input, int* argc, char*** argv) {
  uint32_t count = 0, total = 4;
  *argc = 0; *argv = NULL;
  if (!read_u32(input, &count) || count == 0 || count > 256) return 0;
  char** args = calloc(count + 2, sizeof(char*));
  if (!args) return 0;
  args[0] = calloc(32, 1);
  if (!args[0]) { free(args); return 0; }
  strcpy(args[0], "wormhole-freerdp-host");
  for (uint32_t i = 1; i <= count; ++i) {
    uint32_t length;
    if (!read_u32(input, &length) || length == 0 || total > WH_MAX_SETTINGS - 4 || length > WH_MAX_SETTINGS - total - 4) goto fail;
    total += length + 4;
    args[i] = calloc(length + 1, 1);
    if (!args[i] || fread(args[i], 1, length, input) != length || memchr(args[i], 0, length)) goto fail;
  }
  *argc = (int)count + 1; *argv = args;
  return 1;
fail:
  wh_free_settings((int)count + 1, args);
  return 0;
}

int wh_read_command(FILE* input, uint32_t command[5]) {
  for (int i = 0; i < 5; ++i) if (!read_u32(input, &command[i])) return 0;
  switch (command[0]) {
    case 1:
      if (command[2] >= WH_MAX_DIMENSION || command[3] >= WH_MAX_DIMENSION) return 0;
      switch (command[1]) {
        case 0x0800: case 0x1000: case 0x2000: case 0x4000:
        case 0x9000: case 0xa000: case 0xc000: case 0x0278: case 0x0388: return 1;
        default: return 0;
      }
    case 2: return command[1] > 0 && command[1] <= 0x1ff && command[2] <= 1;
    case 3: return command[1] > 0 && command[1] <= 0xffff && command[2] <= 1;
    case 4: return wh_valid_dimensions(command[1], command[2]);
    case 5: case 6: case 7: return 1;
    case 8: return command[1] != 0;
    case 9: return command[1] <= 1;
    default: return 0;
  }
}

int wh_write_header(FILE* output, const uint32_t values[7]) {
  unsigned char bytes[28];
  for (int i = 0; i < 7; ++i) {
    bytes[i*4] = (unsigned char)(values[i] >> 24);
    bytes[i*4+1] = (unsigned char)(values[i] >> 16);
    bytes[i*4+2] = (unsigned char)(values[i] >> 8);
    bytes[i*4+3] = (unsigned char)values[i];
  }
  return fwrite(bytes, 1, sizeof(bytes), output) == sizeof(bytes);
}

int wh_valid_dimensions(uint32_t width, uint32_t height) {
  return width > 0 && height > 0 && width <= WH_MAX_DIMENSION && height <= WH_MAX_DIMENSION &&
         (uint64_t)width * height <= WH_MAX_PIXELS;
}
