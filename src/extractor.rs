use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::scanner;
use crate::signature;

pub struct ExtractOptions {
    pub recursive: bool,
    pub max_depth: u32,
    pub max_files: usize,
    pub dry_run: bool,
    /// Мінімальна впевненість (0-100) для екстракції знахідки. Знахідки без
    /// жодної структурної перевірки (евристичний фолбек, 40%) типово
    /// заповнюють щільні бінарні файли хибними збігами на слабкі сигнатури —
    /// без фільтра екстракція намагалася б зберегти кожен такий "збіг" як
    /// окремий файл.
    pub min_confidence: u8,
}

pub struct ExtractSummary {
    pub extracted_count: usize,
    pub truncated_by_max_files: bool,
}

struct State {
    count: usize,
    truncated: bool,
}

/// Розкладає `data` на окремі файли за знайденими сигнатурами (raw carve —
/// без розпакування контейнерів), рекурсивно повторюючи те саме для кожного
/// витягнутого фрагмента, доки не буде досягнуто `max_depth` або `max_files`.
pub fn extract(data: &[u8], output_dir: &Path, opts: &ExtractOptions) -> Result<ExtractSummary> {
    let mut state = State {
        count: 0,
        truncated: false,
    };
    extract_recursive(data, output_dir, 0, opts, &mut state)?;
    Ok(ExtractSummary {
        extracted_count: state.count,
        truncated_by_max_files: state.truncated,
    })
}

fn extract_recursive(
    data: &[u8],
    output_dir: &Path,
    depth: u32,
    opts: &ExtractOptions,
    state: &mut State,
) -> Result<()> {
    if state.count >= opts.max_files {
        state.truncated = true;
        return Ok(());
    }

    // Прогрес-бар доречний лише для кореневого сканування великого файлу;
    // для рекурсивних викликів на невеликих фрагментах він був би шумом.
    let findings: Vec<_> = if depth == 0 {
        scanner::scan(data)
    } else {
        scanner::scan_quiet(data)
    }
    .into_iter()
    .filter(|f| f.confidence >= opts.min_confidence)
    .collect();

    for finding in &findings {
        if state.count >= opts.max_files {
            state.truncated = true;
            break;
        }

        let fragment = &data[finding.offset_start..=finding.offset_end];
        let extension = signature::extension_for(&finding.format);
        let file_name = format!(
            "{:08x}_{}.{}",
            finding.offset_start,
            finding.format.to_lowercase(),
            extension
        );
        let out_path = output_dir.join(&file_name);

        if opts.dry_run {
            println!(
                "[0x{:08x}-0x{:08x}] {:>10} bytes  {}  ->  {}",
                finding.offset_start,
                finding.offset_end,
                finding.size,
                finding.format,
                out_path.display()
            );
        } else {
            std::fs::create_dir_all(output_dir)
                .with_context(|| format!("не вдалося створити директорію {}", output_dir.display()))?;
            std::fs::write(&out_path, fragment)
                .with_context(|| format!("не вдалося записати файл {}", out_path.display()))?;
        }
        state.count += 1;

        // Знахідка, що охоплює весь фрагмент цілком, — це контейнер, що
        // "розпізнав сам себе", а не відмінний вкладений файл; рекурсія в
        // неї лише продукувала б нескінченний ланцюжок майже ідентичних
        // копій до вичерпання max_depth.
        let spans_whole_fragment = finding.offset_start == 0 && finding.offset_end + 1 == data.len();

        if opts.recursive && !spans_whole_fragment && depth + 1 < opts.max_depth {
            let child_dir = child_dir_for(output_dir, &file_name);
            extract_recursive(fragment, &child_dir, depth + 1, opts, state)?;
        }
    }

    Ok(())
}

fn child_dir_for(output_dir: &Path, file_name: &str) -> PathBuf {
    output_dir.join(format!("{file_name}_extracted"))
}
