//! QR decoding from image files, clipboard bitmaps and full-screen captures.

use crate::error::{AppError, Result};
use image::{GrayImage, Luma};
use std::path::Path;

/// Decode every QR code found in a greyscale image.
fn decode_luma(img: GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(img);
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_meta, content)| content))
        .collect()
}

/// Some screenshots are low-contrast enough that the default binarisation
/// misses the finder patterns; a 2x upscale is a cheap second attempt.
fn decode_with_retry(img: GrayImage) -> Vec<String> {
    let found = decode_luma(img.clone());
    if !found.is_empty() {
        return found;
    }

    let (w, h) = (img.width(), img.height());
    if w == 0 || h == 0 || w > 4000 || h > 4000 {
        return Vec::new();
    }
    let upscaled = image::imageops::resize(
        &img,
        w * 2,
        h * 2,
        image::imageops::FilterType::CatmullRom,
    );
    decode_luma(upscaled)
}

pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| AppError::invalid(format!("이미지를 읽을 수 없습니다: {e}")))?;
    Ok(decode_with_retry(img.to_luma8()))
}

pub fn decode_image_file(path: &Path) -> Result<Vec<String>> {
    let img = image::open(path)
        .map_err(|e| AppError::invalid(format!("이미지를 열 수 없습니다: {e}")))?;
    Ok(decode_with_retry(img.to_luma8()))
}

/// Decode from a raw RGBA buffer, which is what the clipboard hands us.
pub fn decode_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>> {
    let expected = width as usize * height as usize * 4;
    if rgba.len() < expected {
        return Err(AppError::invalid("클립보드 이미지 크기가 맞지 않습니다."));
    }
    Ok(decode_with_retry(rgba_to_luma(width, height, rgba)))
}

fn rgba_to_luma(width: u32, height: u32, rgba: &[u8]) -> GrayImage {
    let mut gray = GrayImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            let i = ((y as usize * width as usize) + x as usize) * 4;
            // Rec. 601 luma, integer arithmetic to stay fast on big captures.
            let value =
                ((rgba[i] as u32 * 299 + rgba[i + 1] as u32 * 587 + rgba[i + 2] as u32 * 114)
                    / 1000) as u8;
            gray.put_pixel(x, y, Luma([value]));
        }
    }
    gray
}

/// Capture every monitor and return whatever QR payloads are visible.
/// On macOS this requires the Screen Recording permission; the OS prompts the
/// first time and the call simply returns nothing until it is granted.
pub fn scan_screens() -> Result<Vec<String>> {
    let monitors = xcap::Monitor::all()
        .map_err(|e| AppError::msg(format!("화면 목록을 가져오지 못했습니다: {e}")))?;

    if monitors.is_empty() {
        return Err(AppError::msg("캡처할 수 있는 화면이 없습니다."));
    }

    let mut found = Vec::new();
    let mut errors = Vec::new();

    for monitor in monitors {
        match monitor.capture_image() {
            Ok(rgba) => {
                let (w, h) = (rgba.width(), rgba.height());
                let buffer = rgba.into_raw();
                found.extend(decode_with_retry(rgba_to_luma(w, h, &buffer)));
            }
            Err(e) => errors.push(e.to_string()),
        }
    }

    found.sort();
    found.dedup();

    if found.is_empty() && !errors.is_empty() {
        return Err(AppError::msg(format!(
            "화면 캡처에 실패했습니다: {}",
            errors.join(", ")
        )));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draw the given modules as a scaled bitmap so the decoder has something
    /// realistic to chew on.
    fn render(modules: &[Vec<bool>], scale: u32, quiet: u32) -> GrayImage {
        let n = modules.len() as u32;
        let size = (n + quiet * 2) * scale;
        let mut img = GrayImage::from_pixel(size, size, Luma([255]));
        for (y, row) in modules.iter().enumerate() {
            for (x, &dark) in row.iter().enumerate() {
                if !dark {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.put_pixel(
                            (x as u32 + quiet) * scale + dx,
                            (y as u32 + quiet) * scale + dy,
                            Luma([0]),
                        );
                    }
                }
            }
        }
        img
    }

    #[test]
    fn blank_image_yields_no_codes() {
        let img = GrayImage::from_pixel(200, 200, Luma([255]));
        assert!(decode_luma(img).is_empty());
    }

    #[test]
    fn noise_does_not_panic_the_decoder() {
        let modules: Vec<Vec<bool>> = (0..21)
            .map(|y| (0..21).map(|x| (x * 7 + y * 13) % 3 == 0).collect())
            .collect();
        let img = render(&modules, 4, 4);
        // Whatever comes back, the call must not panic.
        let _ = decode_with_retry(img);
    }

    #[test]
    fn rgba_conversion_preserves_dimensions_and_luma() {
        let rgba = vec![255u8, 0, 0, 255, 0, 0, 0, 255];
        let gray = rgba_to_luma(2, 1, &rgba);
        assert_eq!(gray.dimensions(), (2, 1));
        assert_eq!(gray.get_pixel(0, 0)[0], 76); // pure red
        assert_eq!(gray.get_pixel(1, 0)[0], 0); // black
    }

    #[test]
    fn rgba_rejects_short_buffers() {
        assert!(decode_rgba(10, 10, &[0u8; 16]).is_err());
    }

    #[test]
    fn garbage_bytes_are_rejected_as_images() {
        assert!(decode_image_bytes(b"not an image at all").is_err());
    }
}
