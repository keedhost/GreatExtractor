use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Table};
use std::io;

use crate::cli::OutputFormat;
use crate::entropy::EntropyBlock;
use crate::scanner::Finding;
use crate::signature;

pub fn render(findings: &[Finding], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => render_table(findings),
        OutputFormat::Json => render_json(findings),
        OutputFormat::Csv => render_csv(findings),
    }
}

/// Виводить перелік УСІХ підтримуваних форматів (не лише знайдених у
/// якомусь конкретному файлі) з описами — для `great-extractor --formats`/`-f`.
/// Той самий `signature::usage_note`, що й панель "Про формат" у TUI, тож
/// опис одного й того ж формату завжди однаковий в обох місцях.
pub fn render_formats() -> Result<()> {
    let formats = signature::all_formats();
    println!("Підтримується {} форматів:\n", formats.len());
    for (name, note) in &formats {
        println!("{name}");
        println!("  {note}\n");
    }
    Ok(())
}

fn render_table(findings: &[Finding]) -> Result<()> {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(vec![
        "Offset start",
        "Offset end",
        "Size",
        "Format",
        "Description",
        "Confidence",
        "Name",
    ]);

    for f in findings {
        table.add_row(vec![
            format!("0x{:08x}", f.offset_start),
            format!("0x{:08x}", f.offset_end),
            f.size.to_string(),
            f.format.clone(),
            f.description.clone(),
            format!("{}%", f.confidence),
            f.name.clone().unwrap_or_default(),
        ]);
    }

    println!("{table}");
    Ok(())
}

fn render_json(findings: &[Finding]) -> Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    println!("{json}");
    Ok(())
}

/// Нейтралізує CSV/formula injection (CWE-1236, "OWASP CSV Injection"): поле
/// `name` витягується з вмісту самого сканованого файлу (ім'я запису
/// TAR/CPIO/ar/WAD/PAK) і повністю контролюється його автором — на відміну
/// від `format`/`description`, що завжди беруться з нашої статичної таблиці
/// сигнатур. Крейт `csv` сам коректно екранує коми й лапки (валідність CSV),
/// але НЕ захищає від значень на кшталт `=HYPERLINK(...)`, які Excel/Google
/// Sheets/LibreOffice виконають як формулу при відкритті файлу. Якщо
/// значення починається з символу, що починає формулу, додає провідний
/// апостроф — стандартне пом'якшення.
fn sanitize_csv_field(value: String) -> String {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{value}"),
        _ => value,
    }
}

fn render_csv(findings: &[Finding]) -> Result<()> {
    let mut writer = csv::Writer::from_writer(io::stdout());
    writer.write_record([
        "offset_start",
        "offset_end",
        "size",
        "format",
        "description",
        "confidence",
        "name",
    ])?;
    for f in findings {
        writer.write_record([
            format!("0x{:08x}", f.offset_start),
            format!("0x{:08x}", f.offset_end),
            f.size.to_string(),
            f.format.clone(),
            f.description.clone(),
            f.confidence.to_string(),
            sanitize_csv_field(f.name.clone().unwrap_or_default()),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn render_entropy(blocks: &[EntropyBlock], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => render_entropy_table(blocks),
        OutputFormat::Json => render_entropy_json(blocks),
        OutputFormat::Csv => render_entropy_csv(blocks),
    }
}

fn render_entropy_table(blocks: &[EntropyBlock]) -> Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec!["Offset", "Size", "Entropy (bits/byte)", "Графік", "Підозріло"]);

    for b in blocks {
        table.add_row(vec![
            format!("0x{:08x}", b.offset),
            b.size.to_string(),
            format!("{:.3}", b.entropy),
            entropy_bar(b.entropy),
            if b.high { "★".to_string() } else { String::new() },
        ]);
    }

    println!("{table}");
    Ok(())
}

/// Текстовий градієнт з символів зростаючої "щільності" — простий аналог
/// ASCII-графіка ентропії для CLI-виводу (повноцінний інтерактивний графік —
/// у TUI, Етап 6).
fn entropy_bar(entropy: f64) -> String {
    const LEVELS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let level = ((entropy / 8.0).clamp(0.0, 1.0) * (LEVELS.len() - 1) as f64).round() as usize;
    LEVELS[level].to_string().repeat(20.min(1 + level * 2))
}

fn render_entropy_json(blocks: &[EntropyBlock]) -> Result<()> {
    let json = serde_json::to_string_pretty(blocks)?;
    println!("{json}");
    Ok(())
}

fn render_entropy_csv(blocks: &[EntropyBlock]) -> Result<()> {
    let mut writer = csv::Writer::from_writer(io::stdout());
    writer.write_record(["offset", "size", "entropy", "high"])?;
    for b in blocks {
        writer.write_record([
            format!("0x{:08x}", b.offset),
            b.size.to_string(),
            format!("{:.6}", b.entropy),
            b.high.to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_csv_field_neutralizes_formula_prefixes() {
        for dangerous in ["=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(1,1)", "\ttab", "\rcr"] {
            let sanitized = sanitize_csv_field(dangerous.to_string());
            assert!(sanitized.starts_with('\''), "{dangerous:?} -> {sanitized:?}");
            assert_eq!(&sanitized[1..], dangerous);
        }
    }

    #[test]
    fn sanitize_csv_field_leaves_normal_values_untouched() {
        for normal in ["readme.txt", "some/path/file.bin", "", "1file.txt"] {
            assert_eq!(sanitize_csv_field(normal.to_string()), normal);
        }
    }

    #[test]
    fn render_formats_succeeds() {
        assert!(render_formats().is_ok());
    }
}
