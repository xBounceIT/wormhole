#ifndef WORMHOLE_RDP_WIRE_H
#define WORMHOLE_RDP_WIRE_H
#include <stdint.h>
#include <stdio.h>

// Private pipe protocol, big endian. No untrusted lengths may reach allocation.
#define WH_MAX_SETTINGS (256U * 1024U)
#define WH_MAX_DIMENSION 16384U
#define WH_MAX_PIXELS (64U * 1024U * 1024U)
#define WH_TILE_SIZE 128U
int wh_read_settings(FILE* input, int* argc, char*** argv);
void wh_free_settings(int argc, char** argv);
int wh_read_command(FILE* input, uint32_t command[5]);
int wh_write_header(FILE* output, const uint32_t values[7]);
int wh_valid_dimensions(uint32_t width, uint32_t height);
#endif
