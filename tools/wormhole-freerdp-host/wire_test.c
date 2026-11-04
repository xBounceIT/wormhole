#include "wire.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static FILE* packet(const uint32_t* values, size_t count, const char* tail, size_t length) {
  FILE* file = tmpfile(); assert(file);
  for (size_t i = 0; i < count; ++i) {
    unsigned char bytes[4] = {(unsigned char)(values[i] >> 24), (unsigned char)(values[i] >> 16), (unsigned char)(values[i] >> 8), (unsigned char)values[i]};
    assert(fwrite(bytes, 1, 4, file) == 4);
  }
  if (length) assert(fwrite(tail, 1, length, file) == length);
  rewind(file); return file;
}

int main(void) {
  int argc; char** argv;
  uint32_t values[7] = {1, 5};
  FILE* file = packet(values, 2, "/v:hi", 5);
  assert(wh_read_settings(file, &argc, &argv));
  assert(argc == 2 && strcmp(argv[1], "/v:hi") == 0);
  wh_free_settings(argc, argv); fclose(file);
  wh_free_settings(0, NULL);
  const uint32_t bad[][3] = {{0}, {257}, {1, 0}, {1, WH_MAX_SETTINGS}, {1, 5}, {2, 5}};
  for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) {
    file = packet(bad[i], 2, "a\0b", 3);
    assert(!wh_read_settings(file, &argc, &argv)); fclose(file);
  }
  file = packet(values, 0, "x", 1);
  assert(!wh_read_settings(file, &argc, &argv)); fclose(file);
  file = packet(values, 2, "a\0bcd", 5);
  assert(!wh_read_settings(file, &argc, &argv)); fclose(file);
  uint32_t command[5];
  uint32_t commands[][5] = {
    {1,0x0800,0,0},{1,0x1000,0,0},{1,0x2000,0,0},{1,0x4000,0,0},{1,0x9000,0,0},
    {1,0xa000,0,0},{1,0xc000,0,0},{1,0x0278,0,0},{1,0x0388,0,0},
    {2,0x11d,1},{3,0x20ac,0},{4,1920,1080},{5},{6},{7},{8,1},{9,0},{9,1}
  };
  for (size_t i = 0; i < sizeof(commands)/sizeof(commands[0]); ++i) {
    file = packet(commands[i], 5, NULL, 0); assert(wh_read_command(file, command));
    assert(memcmp(command, commands[i], sizeof(command)) == 0); fclose(file);
  }
  uint32_t invalid[][5] = {{1,0x0800,WH_MAX_DIMENSION,0},{1,0x0800,0,WH_MAX_DIMENSION},
    {1,0xffff,0,0},{2,0,1},{2,512,1},{2,1,2},{3,0,1},{3,65536,1},{3,1,2},
    {4,0,1},{4,1,0},{4,16385,1},{4,1,16385},{4,16384,16384},{8,0},{9,2},{99}};
  for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
    file = packet(invalid[i], 5, NULL, 0); assert(!wh_read_command(file, command)); fclose(file);
  }
  file = packet(commands[0], 4, NULL, 0); assert(!wh_read_command(file, command)); fclose(file);
  assert(wh_valid_dimensions(8192, 8192));
  uint32_t header[7] = {2,1920,1080,0,0,128,128};
  file = tmpfile(); assert(file); assert(wh_write_header(file, header));
  assert(ftell(file) == 28); rewind(file);
  unsigned char bytes[28]; assert(fread(bytes,1,28,file) == 28);
  assert(bytes[3] == 2 && bytes[6] == 7 && bytes[7] == 128 && bytes[27] == 128);
  fclose(file);
  puts("Native RDP wire tests passed");
  return 0;
}
