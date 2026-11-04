#include "surface.h"

int wh_certificate_reply(int* cancelled, const uint32_t command[5]) {
  if (*cancelled) return 0;
  if (command[0] == 6 || (command[0] == 9 && !command[1])) {
    *cancelled = 1;
    return 0;
  }
  return command[0] == 9 ? 2 : -1;
}

int wh_paint_begin(WhPaint* paint) {
  if (!paint->visible) return 0;
  if (paint->pending) { paint->dirty = 1; return 0; }
  if (++paint->sequence == 0) ++paint->sequence;
  paint->pending = paint->sequence;
  paint->dirty = 0;
  return 1;
}
int wh_paint_ack(WhPaint* paint, uint32_t sequence) {
  if (!sequence || sequence != paint->pending) return 0;
  paint->pending = 0;
  return paint->visible && paint->dirty;
}
int wh_paint_show(WhPaint* paint) {
  // The first paint may arrive before React has enabled the canvas. A show must
  // request a fresh full paint even if native visibility was already true.
  if (paint->visible && paint->pending) { paint->dirty = 1; return 0; }
  paint->visible = 1;
  paint->pending = 0;
  return 1;
}
int wh_display_size(uint32_t* width, uint32_t* height, uint64_t max_area) {
  if (*width < 200) *width = 200;
  if (*height < 200) *height = 200;
  if (*width > 8192) *width = 8192;
  if (*height > 8192) *height = 8192;
  *width &= ~1U;
  return (uint64_t)*width * *height <= max_area;
}
