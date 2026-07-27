//! Аналіз ентропії Шеннона по ковзних (непересічних) блоках файлу — для
//! виявлення стиснених/зашифрованих ділянок, які не мають відомої магічної
//! сигнатури.

use rayon::prelude::*;
use serde::Serialize;

use crate::scanner::Finding;

pub const DEFAULT_WINDOW: usize = 4096;
pub const DEFAULT_THRESHOLD: f64 = 7.5;

/// Ентропія одного блоку даних.
#[derive(Serialize, Debug, Clone)]
pub struct EntropyBlock {
    pub offset: usize,
    pub size: usize,
    /// Біт/байт, 0.0 (повністю однорідні дані) — 8.0 (максимально випадкові).
    pub entropy: f64,
    /// `entropy >= threshold`, використаний при обчисленні.
    pub high: bool,
}

/// Ділить `data` на непересічні блоки розміром `window` і обчислює ентропію
/// Шеннона кожного блоку. Обчислення блоків незалежні одне від одного, тож
/// розподіляються між потоками rayon.
pub fn compute(data: &[u8], window: usize, threshold: f64) -> Vec<EntropyBlock> {
    if window == 0 || data.is_empty() {
        return Vec::new();
    }

    let chunks: Vec<(usize, &[u8])> = {
        let mut offset = 0usize;
        let mut out = Vec::with_capacity(data.len() / window + 1);
        for chunk in data.chunks(window) {
            out.push((offset, chunk));
            offset += chunk.len();
        }
        out
    };

    chunks
        .into_par_iter()
        .map(|(offset, chunk)| {
            let entropy = shannon_entropy(chunk);
            EntropyBlock {
                offset,
                size: chunk.len(),
                entropy,
                high: entropy >= threshold,
            }
        })
        .collect()
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Об'єднує суміжні високоентропійні блоки в неперервні "підозрілі" регіони
/// та подає їх у форматі [`Finding`], щоб їх можна було домішати до
/// загального списку знахідок сканера (`type: high_entropy_region`).
pub fn findings(blocks: &[EntropyBlock]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut current: Option<(usize, usize)> = None;

    for block in blocks {
        if block.high {
            let end = block.offset + block.size - 1;
            match &mut current {
                Some((_, cur_end)) => *cur_end = end,
                None => current = Some((block.offset, end)),
            }
        } else if let Some(region) = current.take() {
            out.push(region_finding(region));
        }
    }
    if let Some(region) = current {
        out.push(region_finding(region));
    }

    out
}

fn region_finding((start, end): (usize, usize)) -> Finding {
    Finding {
        format: "high_entropy_region".to_string(),
        description: "Ділянка з високою ентропією (можливо, стиснені/зашифровані дані)".to_string(),
        offset_start: start,
        offset_end: end,
        size: end - start + 1,
        // Немає структурного підтвердження — типу confidence сигнатур не
        // застосовний тут, тож фіксоване середнє значення просто позначає
        // ділянку як "варту уваги", а не як точну знахідку формату.
        confidence: 50,
        name: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bytes_have_zero_entropy() {
        let data = vec![0u8; 1024];
        let blocks = compute(&data, 1024, DEFAULT_THRESHOLD);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].entropy, 0.0);
        assert!(!blocks[0].high);
    }

    #[test]
    fn all_byte_values_have_max_entropy() {
        let data: Vec<u8> = (0..=255u8).collect();
        let blocks = compute(&data, 256, DEFAULT_THRESHOLD);
        assert_eq!(blocks.len(), 1);
        assert!((blocks[0].entropy - 8.0).abs() < 1e-9);
        assert!(blocks[0].high);
    }

    #[test]
    fn last_chunk_may_be_smaller_than_window() {
        let data = vec![0u8; 100];
        let blocks = compute(&data, 64, DEFAULT_THRESHOLD);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].size, 64);
        assert_eq!(blocks[1].size, 36);
        assert_eq!(blocks[1].offset, 64);
    }

    #[test]
    fn adjacent_high_entropy_blocks_merge_into_one_region() {
        let mut data = vec![0u8; 3 * 256];
        for (i, chunk) in data.chunks_mut(256).enumerate() {
            if i != 1 {
                for (j, b) in chunk.iter_mut().enumerate() {
                    *b = j as u8; // 0..=255 — максимальна ентропія
                }
            }
        }
        let blocks = compute(&data, 256, DEFAULT_THRESHOLD);
        assert!(blocks[0].high && blocks[2].high && !blocks[1].high);

        let regions = findings(&blocks);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].offset_start, 0);
        assert_eq!(regions[0].offset_end, 255);
        assert_eq!(regions[1].offset_start, 512);
        assert_eq!(regions[1].offset_end, 767);
    }
}
