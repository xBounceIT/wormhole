#ifndef WORMHOLE_RDP_SURFACE_H
#define WORMHOLE_RDP_SURFACE_H
#include <stdint.h>
typedef struct {
  int visible, dirty;
  uint32_t sequence, pending;
} WhPaint;
int wh_paint_begin(WhPaint* paint);
int wh_paint_ack(WhPaint* paint, uint32_t sequence);
int wh_paint_show(WhPaint* paint);
int wh_display_size(uint32_t* width, uint32_t* height, uint64_t max_area);
int wh_certificate_reply(int* cancelled, const uint32_t command[5]);
#endif
