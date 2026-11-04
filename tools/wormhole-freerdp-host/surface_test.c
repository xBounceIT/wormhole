#include "surface.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int cancelled = 0;
  assert(wh_certificate_reply(&cancelled, (uint32_t[5]){4, 800, 600}) == -1);
  assert(wh_certificate_reply(&cancelled, (uint32_t[5]){9, 1}) == 2);
  assert(!cancelled);
  assert(wh_certificate_reply(&cancelled, (uint32_t[5]){6}) == 0);
  assert(cancelled);
  assert(wh_certificate_reply(&cancelled, (uint32_t[5]){9, 1}) == 0);
  cancelled = 0;
  assert(wh_certificate_reply(&cancelled, (uint32_t[5]){9, 0}) == 0 && cancelled);
  WhPaint paint = {0};
  assert(!wh_paint_begin(&paint));
  assert(wh_paint_show(&paint));
  assert(wh_paint_begin(&paint));
  uint32_t first = paint.pending;
  assert(!wh_paint_show(&paint)); // duplicate focus cannot bypass backpressure
  assert(!wh_paint_begin(&paint) && paint.dirty);
  assert(!wh_paint_ack(&paint, first + 1));
  assert(wh_paint_ack(&paint, first));
  assert(wh_paint_begin(&paint));
  paint.visible = 0;
  assert(wh_paint_show(&paint));
  assert(wh_paint_begin(&paint));
  assert(!wh_paint_ack(&paint, first)); // old hidden-frame ack cannot free this paint
  assert(paint.pending && !paint.dirty);
  assert(!wh_paint_ack(&paint, paint.pending));
  assert(!paint.pending);
  assert(wh_paint_show(&paint)); // recover pixels dropped before the canvas mounts
  paint.sequence = UINT32_MAX;
  assert(wh_paint_begin(&paint) && paint.pending == 1);
  paint.visible = 0;
  paint.dirty = 1;
  assert(!wh_paint_ack(&paint, 1));
  assert(!wh_paint_ack(&paint, 0));
  uint32_t width = 1, height = 1;
  assert(!wh_display_size(&width, &height, 0)); // no caps: scale locally
  assert(width == 200 && height == 200);
  width = height = 16384;
  assert(wh_display_size(&width, &height, 8192ULL * 8192));
  assert(width == 8192 && height == 8192);
  width = 801; height = 600;
  assert(wh_display_size(&width, &height, 800 * 600));
  assert(width == 800 && height == 600);
  assert(!wh_display_size(&width, &height, 800 * 600 - 1));
  puts("Native RDP surface tests passed");
  return 0;
}
