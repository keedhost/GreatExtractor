use std::io::IsTerminal;

use aho_corasick::AhoCorasick;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;

use crate::signature::{Signature, SIGNATURES};

/// Мінімальний розмір одного чанка для паралельного сканування —
/// нижче цієї межі накладні витрати на розподіл роботи між потоками не окупаються.
const MIN_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// Одна знахідка — вбудований файл, виявлений у скановуваних даних.
#[derive(Serialize, Debug, Clone)]
pub struct Finding {
    pub format: String,
    pub description: String,
    pub offset_start: usize,
    pub offset_end: usize,
    pub size: usize,
    /// 0-100. Без структурного валідатора (Етап 3) верхня межа впевненості обмежена.
    pub confidence: u8,
    /// Ім'я файлу/запису, вбудоване у структуру формату (TAR/CPIO/ar/WAD/PAK
    /// тощо), якщо сигнатура має `name_extractor` і його вдалося застосувати.
    pub name: Option<String>,
}

/// Проміжний результат розпізнавання однієї знахідки перед застосуванням фолбеку меж.
struct PendingFinding {
    format: String,
    description: String,
    offset_start: usize,
    confidence: u8,
    /// Точний кінець, якщо його вдалося визначити за end_marker сигнатури.
    resolved_end: Option<usize>,
    name: Option<String>,
}

/// Багатопотоковий пошук усіх відомих сигнатур у `data`.
///
/// `data` очікується як мапований у пам'ять (mmap) зріз файлу — це дозволяє
/// сканувати файли розміром у десятки-сотні ГБ без завантаження їх цілком у
/// купу процесу; фізична пам'ять при цьому обмежена сторінками, які ОС
/// підвантажує під час читання.
///
/// Викликати всередині `rayon::ThreadPool::install`, щоб керувати кількістю потоків.
pub fn scan(data: &[u8]) -> Vec<Finding> {
    scan_impl(data, true)
}

/// Те саме, що [`scan`], але без прогрес-бару — для повторних сканувань
/// невеликих фрагментів під час рекурсивної екстракції, де окремий
/// прогрес-бар на кожен фрагмент був би лише шумом.
pub fn scan_quiet(data: &[u8]) -> Vec<Finding> {
    scan_impl(data, false)
}

fn scan_impl(data: &[u8], show_progress: bool) -> Vec<Finding> {
    if data.is_empty() {
        return Vec::new();
    }

    let patterns: Vec<&[u8]> = SIGNATURES.iter().map(|s| s.magic).collect();
    let ac = AhoCorasick::new(&patterns).expect("valid signature patterns");

    let max_pattern_len = SIGNATURES.iter().map(|s| s.magic.len()).max().unwrap_or(1);
    let overlap = max_pattern_len.saturating_sub(1);
    let ranges = chunk_ranges(data.len(), overlap);

    let pb = if show_progress {
        progress_bar(ranges.len() as u64, "Сканування")
    } else {
        ProgressBar::hidden()
    };

    let chunk_results: Vec<Vec<(usize, &Signature)>> = ranges
        .into_par_iter()
        .map(|(core_start, core_end, search_end)| {
            let local = find_in_chunk(&ac, data, core_start, core_end, search_end);
            pb.inc(1);
            local
        })
        .collect();
    pb.finish_and_clear();

    let mut raw_matches: Vec<(usize, &Signature)> = chunk_results.into_iter().flatten().collect();
    raw_matches.sort_by_key(|(start, sig)| (*start, sig.name));

    let pending: Vec<PendingFinding> = raw_matches
        .into_par_iter()
        .map(|(start, sig)| resolve_finding(data, start, sig))
        .collect();

    apply_fallback_ends(pending, data.len())
}

/// Ділить файл на непересічні "ядра" (core) для розподілу між потоками,
/// кожне ядро супроводжується "хвостом" перекриття (`overlap`), достатнім,
/// щоб жодна сигнатура не була розрізана межею чанка.
/// Повертає трійки (core_start, core_end, search_end).
fn chunk_ranges(len: usize, overlap: usize) -> Vec<(usize, usize, usize)> {
    let target_chunks = rayon::current_num_threads().saturating_mul(4).max(1);
    let chunk_size = (len / target_chunks).max(MIN_CHUNK_SIZE).max(1);

    let mut ranges = Vec::new();
    let mut core_start = 0usize;
    while core_start < len {
        let core_end = (core_start + chunk_size).min(len);
        let search_end = (core_end + overlap).min(len);
        ranges.push((core_start, core_end, search_end));
        core_start = core_end;
    }
    ranges
}

/// Шукає збіги сигнатур у `data[core_start..search_end]`, залишаючи лише ті,
/// що починаються в межах "ядра" `[core_start, core_end)` — збіги, що
/// починаються у хвості перекриття, належать наступному чанку і будуть
/// знайдені ним, тому тут відкидаються, щоб уникнути дублювання.
fn find_in_chunk<'s>(
    ac: &AhoCorasick,
    data: &[u8],
    core_start: usize,
    core_end: usize,
    search_end: usize,
) -> Vec<(usize, &'s Signature)> {
    ac.find_overlapping_iter(&data[core_start..search_end])
        .filter_map(|m| {
            let global_start = core_start + m.start();
            if global_start >= core_end {
                return None;
            }
            Some((global_start, &SIGNATURES[m.pattern().as_usize()]))
        })
        .filter(|(global_start, sig)| {
            // магічні байти лежать усередині заголовка формату (напр. TAR) —
            // збіг недійсний, якщо файл почався б до початку даних
            *global_start >= sig.relative_offset
        })
        .map(|(global_start, sig)| (global_start - sig.relative_offset, sig))
        .collect()
}

fn resolve_finding(data: &[u8], start: usize, sig: &Signature) -> PendingFinding {
    let magic_end = start + sig.relative_offset + sig.magic.len();
    let mut resolved_end = None;
    let mut confidence = 40u8;

    if let Some(validator) = sig.validator
        && let Some((end, conf)) = validator(data, start)
    {
        resolved_end = Some(end);
        confidence = conf;
    } else if let Some(marker) = sig.end_marker
        && let Some(rel_pos) = memchr::memmem::find(&data[magic_end..], marker)
    {
        resolved_end = Some(magic_end + rel_pos + marker.len() - 1);
        confidence = 75;
    }

    let name = sig.name_extractor.and_then(|extract| extract(data, start));

    PendingFinding {
        format: sig.name.to_string(),
        description: sig.description.to_string(),
        offset_start: start,
        confidence,
        resolved_end,
        name,
    }
}

/// Для знахідок без точного end_marker підставляє кінець як старт наступної
/// знахідки (за офсетом) мінус один байт, або кінець файлу, якщо знахідка остання.
fn apply_fallback_ends(pending: Vec<PendingFinding>, file_len: usize) -> Vec<Finding> {
    let starts: Vec<usize> = pending.iter().map(|f| f.offset_start).collect();

    pending
        .iter()
        .enumerate()
        .map(|(i, f)| {
            // `.max(f.offset_start)` — запобіжник проти помилки в конкретному
            // валідаторі (напр. поле розміру, зчитане зі сміттєвих байтів,
            // дало end < start): без нього офсет кінця, менший за офсет
            // початку, призвів би до переповнення при відніманні нижче.
            let offset_end = f
                .resolved_end
                .unwrap_or_else(|| {
                    starts[i + 1..]
                        .iter()
                        .find(|&&s| s > f.offset_start)
                        .map(|&s| s.saturating_sub(1))
                        .unwrap_or_else(|| file_len.saturating_sub(1))
                })
                .max(f.offset_start);

            Finding {
                format: f.format.clone(),
                description: f.description.clone(),
                offset_start: f.offset_start,
                offset_end,
                size: offset_end - f.offset_start + 1,
                confidence: f.confidence,
                name: f.name.clone(),
            }
        })
        .collect()
}

fn progress_bar(len: u64, message: &'static str) -> ProgressBar {
    if len == 0 || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:40}] {pos}/{len} чанків ({eta})")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(message);
    pb
}
