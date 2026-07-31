//! Framebuffer sink, raw pixel buffer, and damage-rect tracking.
//!
//! Decode is a stub: only **Raw** (encoding 0) pixel blit is supported. Zrle /
//! Tight / CopyRect land with the live `engine` path.

use bytes::Bytes;

use crate::VncError;

/// Pixel layout advertised to / from the RFB server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormatKind {
    /// 32-bit BGRA (common for Windows surfaces).
    Bgra8888,
    /// 32-bit RGBA.
    Rgba8888,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferPixelFormat {
    pub kind: PixelFormatKind,
    pub bits_per_pixel: u8,
    pub depth: u8,
}

impl FramebufferPixelFormat {
    pub const fn bgra8888() -> Self {
        Self {
            kind: PixelFormatKind::Bgra8888,
            bits_per_pixel: 32,
            depth: 24,
        }
    }

    pub const fn rgba8888() -> Self {
        Self {
            kind: PixelFormatKind::Rgba8888,
            bits_per_pixel: 32,
            depth: 24,
        }
    }

    pub const fn bytes_per_pixel(self) -> usize {
        (self.bits_per_pixel as usize) / 8
    }
}

/// Axis-aligned damage / update rectangle in framebuffer coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DamageRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl DamageRect {
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub fn right(self) -> u32 {
        u32::from(self.x) + u32::from(self.width)
    }

    pub fn bottom(self) -> u32 {
        u32::from(self.y) + u32::from(self.height)
    }

    /// True when rects share area (strict overlap, not mere edge touch).
    pub fn intersects(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        u32::from(self.x) < other.right()
            && u32::from(other.x) < self.right()
            && u32::from(self.y) < other.bottom()
            && u32::from(other.y) < self.bottom()
    }

    /// True when rects overlap or share an edge/corner (inclusive AABB touch).
    ///
    /// Corner-only contact merges as over-damage (safe for dirty tracking).
    pub fn overlaps_or_touches(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        // Inclusive edges: `ax0 <= bx1 && bx0 <= ax1` treats touching sides/corners
        // as mergeable.
        u32::from(self.x) <= other.right()
            && u32::from(other.x) <= self.right()
            && u32::from(self.y) <= other.bottom()
            && u32::from(other.y) <= self.bottom()
    }

    pub fn union(self, other: Self) -> Self {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = self.right().max(other.right());
        let y1 = self.bottom().max(other.bottom());
        let w = x1 - u32::from(x0);
        let h = y1 - u32::from(y0);
        // u16 fields cannot represent spans > u16::MAX. Truncating with `as u16`
        // could yield 0 / wrong size (under-damage). Prefer full-plane over-damage.
        if w > u32::from(u16::MAX) || h > u32::from(u16::MAX) {
            return Self::new(0, 0, u16::MAX, u16::MAX);
        }
        Self {
            x: x0,
            y: y0,
            width: w as u16,
            height: h as u16,
        }
    }

    /// Whether `other` is completely inside `self`.
    pub fn contains(self, other: Self) -> bool {
        if other.is_empty() {
            return true;
        }
        if self.is_empty() {
            return false;
        }
        self.x <= other.x
            && self.y <= other.y
            && self.right() >= other.right()
            && self.bottom() >= other.bottom()
    }
}

/// Accumulates dirty regions and merges overlapping / edge-adjacent rects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DamageTracker {
    rects: Vec<DamageRect>,
}

impl DamageTracker {
    pub fn new() -> Self {
        Self { rects: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }

    pub fn rects(&self) -> &[DamageRect] {
        &self.rects
    }

    pub fn clear(&mut self) {
        self.rects.clear();
    }

    pub fn take(&mut self) -> Vec<DamageRect> {
        std::mem::take(&mut self.rects)
    }

    /// Record damage; empty rects are ignored. Overlapping or touching rects merge.
    pub fn add(&mut self, rect: DamageRect) {
        if rect.is_empty() {
            return;
        }
        self.rects.push(rect);
        self.coalesce();
    }

    fn coalesce(&mut self) {
        loop {
            let mut merged = false;
            let mut i = 0;
            while i < self.rects.len() {
                let mut j = i + 1;
                while j < self.rects.len() {
                    if self.rects[i].overlaps_or_touches(self.rects[j]) {
                        let u = self.rects[i].union(self.rects[j]);
                        self.rects[i] = u;
                        self.rects.swap_remove(j);
                        merged = true;
                    } else {
                        j += 1;
                    }
                }
                i += 1;
            }
            if !merged {
                break;
            }
        }
    }
}

/// Rectangle update from the RFB server (encoded or raw bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramebufferRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    /// Encoded or raw pixel bytes for this rect (encoding left to the engine).
    pub pixels: Bytes,
}

impl FramebufferRect {
    pub fn damage(&self) -> DamageRect {
        DamageRect::new(self.x, self.y, self.width, self.height)
    }
}

/// Consumer of framebuffer updates (UI surface).
pub trait FramebufferSink: Send {
    fn set_size(&mut self, width: u16, height: u16);
    fn apply_rect(&mut self, rect: FramebufferRect) -> Result<(), VncError>;
    fn pixel_format(&self) -> FramebufferPixelFormat;
}

/// Contiguous raw pixel store with damage tracking (decode stub target).
#[derive(Debug, Clone)]
pub struct RawPixelBuffer {
    width: u16,
    height: u16,
    format: FramebufferPixelFormat,
    pixels: Vec<u8>,
    damage: DamageTracker,
}

impl Default for RawPixelBuffer {
    fn default() -> Self {
        Self::empty(FramebufferPixelFormat::bgra8888())
    }
}

impl RawPixelBuffer {
    pub fn empty(format: FramebufferPixelFormat) -> Self {
        Self {
            width: 0,
            height: 0,
            format,
            pixels: Vec::new(),
            damage: DamageTracker::new(),
        }
    }

    pub fn new(width: u16, height: u16, format: FramebufferPixelFormat) -> Self {
        let mut buf = Self::empty(format);
        buf.resize(width, height);
        buf
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    pub fn format(&self) -> FramebufferPixelFormat {
        self.format
    }

    pub fn stride(&self) -> usize {
        usize::from(self.width) * self.format.bytes_per_pixel()
    }

    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub fn pixels_mut(&mut self) -> &mut [u8] {
        &mut self.pixels
    }

    pub fn damage(&self) -> &[DamageRect] {
        self.damage.rects()
    }

    pub fn take_damage(&mut self) -> Vec<DamageRect> {
        self.damage.take()
    }

    pub fn clear_damage(&mut self) {
        self.damage.clear();
    }

    /// Reallocate the backing store; clears pixels and damage.
    ///
    /// If `width * height * bpp` overflows `usize`, fail closed to an empty
    /// `0×0` buffer so later blits cannot panic on a short `pixels` vec.
    pub fn resize(&mut self, width: u16, height: u16) {
        let bpp = self.format.bytes_per_pixel();
        let Some(len) = usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|n| n.checked_mul(bpp))
        else {
            self.width = 0;
            self.height = 0;
            self.pixels.clear();
            self.damage.clear();
            return;
        };
        self.width = width;
        self.height = height;
        self.pixels.clear();
        self.pixels.resize(len, 0);
        self.damage.clear();
    }

    /// Expected byte length for a Raw-encoding rectangle of this buffer's format.
    ///
    /// Returns `None` when `width * height * bpp` overflows `usize`.
    pub fn raw_rect_byte_len(&self, width: u16, height: u16) -> Option<usize> {
        usize::from(width)
            .checked_mul(usize::from(height))
            .and_then(|n| n.checked_mul(self.format.bytes_per_pixel()))
    }

    /// Decode stub: blit **Raw** pixels into the buffer and mark damage.
    ///
    /// `src` must be tightly packed row-major pixels matching [`Self::format`].
    /// Out-of-bounds rects and length mismatches return
    /// [`VncError::InvalidFramebufferUpdate`] (no silent clamp into the store).
    /// No Zrle/Tight/CopyRect handling here — those stay behind `engine`.
    pub fn blit_raw(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        src: &[u8],
    ) -> Result<(), VncError> {
        if width == 0 || height == 0 {
            return Ok(());
        }
        let x_end = u32::from(x)
            .checked_add(u32::from(width))
            .ok_or(VncError::InvalidFramebufferUpdate)?;
        let y_end = u32::from(y)
            .checked_add(u32::from(height))
            .ok_or(VncError::InvalidFramebufferUpdate)?;
        if x_end > u32::from(self.width) || y_end > u32::from(self.height) {
            return Err(VncError::InvalidFramebufferUpdate);
        }

        let bpp = self.format.bytes_per_pixel();
        let expected = self
            .raw_rect_byte_len(width, height)
            .ok_or(VncError::InvalidFramebufferUpdate)?;
        if src.len() != expected {
            return Err(VncError::InvalidFramebufferUpdate);
        }

        let Some(src_stride) = usize::from(width).checked_mul(bpp) else {
            return Err(VncError::InvalidFramebufferUpdate);
        };
        let Some(x_bytes) = usize::from(x).checked_mul(bpp) else {
            return Err(VncError::InvalidFramebufferUpdate);
        };

        // After the bounds + length checks above, every row slice is in-range.
        // Index via checked offsets so a logic bug cannot panic on slice ends.
        let dst_stride = self.stride();
        let pixels_len = self.pixels.len();
        for row in 0..usize::from(height) {
            let src_off = row * src_stride;
            let Some(dst_off) = usize::from(y)
                .checked_add(row)
                .and_then(|r| r.checked_mul(dst_stride))
                .and_then(|base| base.checked_add(x_bytes))
            else {
                return Err(VncError::InvalidFramebufferUpdate);
            };
            let Some(dst_end) = dst_off.checked_add(src_stride) else {
                return Err(VncError::InvalidFramebufferUpdate);
            };
            if dst_end > pixels_len || src_off + src_stride > src.len() {
                return Err(VncError::InvalidFramebufferUpdate);
            }
            self.pixels[dst_off..dst_end].copy_from_slice(&src[src_off..src_off + src_stride]);
        }

        self.damage.add(DamageRect::new(x, y, width, height));
        Ok(())
    }

    /// Convenience: blit from a [`FramebufferRect`] (Raw payload assumed).
    pub fn apply_raw_rect(&mut self, rect: &FramebufferRect) -> Result<(), VncError> {
        self.blit_raw(rect.x, rect.y, rect.width, rect.height, &rect.pixels)
    }
}

impl FramebufferSink for RawPixelBuffer {
    fn set_size(&mut self, width: u16, height: u16) {
        self.resize(width, height);
    }

    fn apply_rect(&mut self, rect: FramebufferRect) -> Result<(), VncError> {
        self.apply_raw_rect(&rect)
    }

    fn pixel_format(&self) -> FramebufferPixelFormat {
        self.format
    }
}

/// In-memory sink that records rects without decoding (tests / session stub).
#[derive(Debug)]
pub struct MemoryFramebuffer {
    pub width: u16,
    pub height: u16,
    pub rects: Vec<FramebufferRect>,
    format: FramebufferPixelFormat,
}

impl Default for MemoryFramebuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryFramebuffer {
    pub fn new() -> Self {
        Self {
            width: 0,
            height: 0,
            rects: Vec::new(),
            format: FramebufferPixelFormat::bgra8888(),
        }
    }
}

impl FramebufferSink for MemoryFramebuffer {
    fn set_size(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
    }

    fn apply_rect(&mut self, rect: FramebufferRect) -> Result<(), VncError> {
        self.rects.push(rect);
        Ok(())
    }

    fn pixel_format(&self) -> FramebufferPixelFormat {
        self.format
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damage_merge_overlapping() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 10, 10));
        d.add(DamageRect::new(5, 5, 10, 10));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 15, 15));
    }

    #[test]
    fn damage_merge_adjacent_edge() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 10, 10));
        // Touches right edge of the first rect.
        d.add(DamageRect::new(10, 0, 5, 10));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 15, 10));
    }

    #[test]
    fn damage_merge_corner_touch_over_damages() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 5, 5));
        d.add(DamageRect::new(5, 5, 5, 5));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 10, 10));
    }

    #[test]
    fn damage_keeps_disjoint_rects() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 4, 4));
        d.add(DamageRect::new(20, 20, 4, 4));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn damage_absorbs_contained_rect() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 20, 20));
        d.add(DamageRect::new(2, 2, 4, 4));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 20, 20));
    }

    #[test]
    fn damage_ignores_empty() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(1, 1, 0, 5));
        d.add(DamageRect::new(1, 1, 5, 0));
        assert!(d.is_empty());
    }

    #[test]
    fn damage_chain_merge_three() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 5, 5));
        d.add(DamageRect::new(10, 0, 5, 5));
        // Bridges the gap → single union.
        d.add(DamageRect::new(4, 0, 7, 5));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 15, 5));
    }

    #[test]
    fn raw_blit_writes_pixels_and_damage() {
        let mut buf = RawPixelBuffer::new(4, 2, FramebufferPixelFormat::bgra8888());
        // One pixel at (1,0): BGRA red-ish.
        let px = [0u8, 0, 255, 255];
        buf.blit_raw(1, 0, 1, 1, &px).unwrap();
        let stride = buf.stride();
        let off = 1 * 4;
        assert_eq!(&buf.pixels()[off..off + 4], &px);
        assert_eq!(buf.pixels()[0], 0);
        assert_eq!(buf.damage(), &[DamageRect::new(1, 0, 1, 1)]);
        assert_eq!(stride, 16);
    }

    #[test]
    fn raw_blit_rejects_oob_and_bad_len() {
        let mut buf = RawPixelBuffer::new(2, 2, FramebufferPixelFormat::bgra8888());
        assert!(buf.blit_raw(1, 1, 2, 1, &[0; 8]).is_err());
        assert!(buf.blit_raw(0, 0, 1, 1, &[0; 3]).is_err());
        assert!(buf.blit_raw(0, 0, 1, 1, &[0; 4]).is_ok());
    }

    #[test]
    fn damage_merge_adjacent_vertical() {
        let mut d = DamageTracker::new();
        d.add(DamageRect::new(0, 0, 8, 4));
        d.add(DamageRect::new(0, 4, 8, 4));
        assert_eq!(d.len(), 1);
        assert_eq!(d.rects()[0], DamageRect::new(0, 0, 8, 8));
    }

    #[test]
    fn damage_union_overflow_does_not_truncate_to_empty() {
        // Adjacent rects whose union width is u16::MAX + 1 must not become width 0.
        let a = DamageRect::new(0, 0, u16::MAX, 1);
        let b = DamageRect::new(u16::MAX, 0, 1, 1);
        assert!(a.overlaps_or_touches(b));
        let u = a.union(b);
        assert!(!u.is_empty());
        assert_eq!(u, DamageRect::new(0, 0, u16::MAX, u16::MAX));
    }

    #[test]
    fn raw_blit_rgba_multirow_stride() {
        let mut buf = RawPixelBuffer::new(3, 2, FramebufferPixelFormat::rgba8888());
        assert_eq!(buf.stride(), 12);
        // 2×2 rect at (1,0): 4 pixels × 4 bytes.
        let mut src = vec![0u8; 16];
        for (i, chunk) in src.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&[i as u8, 1, 2, 3]);
        }
        buf.blit_raw(1, 0, 2, 2, &src).unwrap();
        let stride = buf.stride();
        assert_eq!(&buf.pixels()[1 * 4..1 * 4 + 4], &[0, 1, 2, 3]);
        assert_eq!(&buf.pixels()[2 * 4..2 * 4 + 4], &[1, 1, 2, 3]);
        assert_eq!(
            &buf.pixels()[stride + 1 * 4..stride + 1 * 4 + 4],
            &[2, 1, 2, 3]
        );
        assert_eq!(
            &buf.pixels()[stride + 2 * 4..stride + 2 * 4 + 4],
            &[3, 1, 2, 3]
        );
        // Column 0 untouched.
        assert_eq!(&buf.pixels()[0..4], &[0, 0, 0, 0]);
        assert_eq!(buf.damage(), &[DamageRect::new(1, 0, 2, 2)]);
    }

    #[test]
    fn raw_blit_rejects_exact_edge_oob() {
        let mut buf = RawPixelBuffer::new(4, 4, FramebufferPixelFormat::bgra8888());
        // Touches right edge OK.
        assert!(buf.blit_raw(3, 3, 1, 1, &[9, 8, 7, 6]).is_ok());
        // One pixel past right / bottom rejected (no clamp into buffer).
        assert!(buf.blit_raw(4, 0, 1, 1, &[0; 4]).is_err());
        assert!(buf.blit_raw(0, 4, 1, 1, &[0; 4]).is_err());
        assert!(buf.blit_raw(3, 3, 2, 1, &[0; 8]).is_err());
    }

    #[test]
    fn take_damage_clears() {
        let mut buf = RawPixelBuffer::new(2, 2, FramebufferPixelFormat::bgra8888());
        buf.blit_raw(0, 0, 1, 1, &[1, 2, 3, 4]).unwrap();
        let taken = buf.take_damage();
        assert_eq!(taken, vec![DamageRect::new(0, 0, 1, 1)]);
        assert!(buf.damage().is_empty());
    }
}
