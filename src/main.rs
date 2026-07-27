mod about;
mod cli;
mod config;
mod entropy;
mod extractor;
mod output;
mod scanner;
mod signature;
mod tui;
mod validators;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use memmap2::Mmap;

use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.formats {
        output::render_formats()?;
        return Ok(());
    }

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    match command {
        Command::Scan {
            file,
            format,
            min_confidence,
            threads,
            entropy,
            entropy_window,
            entropy_threshold,
        } => {
            let mmap = map_file(&file)?;
            let data: &[u8] = mmap.as_deref().unwrap_or(&[]);
            let pool = build_thread_pool(threads)?;

            let mut findings: Vec<_> = pool
                .install(|| scanner::scan(data))
                .into_iter()
                .filter(|f| f.confidence >= min_confidence)
                .collect();

            if entropy {
                let blocks = pool.install(|| self::entropy::compute(data, entropy_window, entropy_threshold));
                findings.extend(self::entropy::findings(&blocks));
                findings.sort_by_key(|f| f.offset_start);
            }

            output::render(&findings, format)?;
        }

        Command::Entropy {
            file,
            window,
            threshold,
            format,
        } => {
            let mmap = map_file(&file)?;
            let data: &[u8] = mmap.as_deref().unwrap_or(&[]);

            let blocks = entropy::compute(data, window, threshold);
            output::render_entropy(&blocks, format)?;
        }

        Command::Extract {
            file,
            output,
            min_confidence,
            no_recursive,
            max_depth,
            max_files,
            dry_run,
            threads,
        } => {
            let mmap = map_file(&file)?;
            let data: &[u8] = mmap.as_deref().unwrap_or(&[]);
            let pool = build_thread_pool(threads)?;

            let output_dir = output.unwrap_or_else(|| default_output_dir(&file));
            let opts = extractor::ExtractOptions {
                recursive: !no_recursive,
                max_depth,
                max_files,
                dry_run,
                min_confidence,
            };

            let summary = pool.install(|| extractor::extract(data, &output_dir, &opts))?;

            if dry_run {
                println!("\nВсього було б витягнуто: {} файл(ів)", summary.extracted_count);
            } else {
                println!(
                    "Витягнуто {} файл(ів) у {}",
                    summary.extracted_count,
                    output_dir.display()
                );
            }
            if summary.truncated_by_max_files {
                eprintln!(
                    "Попередження: досягнуто ліміту --max-files ({max_files}); частина вкладеної структури не оброблена."
                );
            }
        }

        Command::Tui {
            file,
            output,
            min_confidence,
        } => {
            let mmap = map_file(&file)?;
            let data: &[u8] = mmap.as_deref().unwrap_or(&[]);
            let output_dir = output.unwrap_or_else(|| default_output_dir(&file));

            tui::run(&file, output_dir, data, min_confidence)?;
        }
    }

    Ok(())
}

/// Мапує файл у пам'ять для читання. Повертає `None` для порожнього файлу
/// (mmap нульової довжини недійсний на деяких платформах).
fn map_file(file: &Path) -> Result<Option<Mmap>> {
    let file_handle =
        std::fs::File::open(file).with_context(|| format!("не вдалося відкрити файл {}", file.display()))?;
    let len = file_handle
        .metadata()
        .with_context(|| format!("не вдалося прочитати метадані файлу {}", file.display()))?
        .len();

    if len == 0 {
        return Ok(None);
    }

    // SAFETY: файл відкрито лише для читання в межах цього процесу; як і в
    // будь-якому інструменті на основі mmap, паралельна зміна файлу іншим
    // процесом під час роботи може призвести до непередбачуваних даних у
    // зрізі, а обрізання (truncate) файлу під час читання відображених
    // сторінок — до SIGBUS і аварійного завершення процесу (не UB, оскільки
    // Rust не гарантує безпеку від сигналів ОС, — прийнятний компроміс
    // заради обробки файлів, що не вміщуються в пам'ять).
    let mmap = unsafe { Mmap::map(&file_handle) }
        .with_context(|| format!("не вдалося відобразити файл {} у пам'ять", file.display()))?;
    Ok(Some(mmap))
}

fn build_thread_pool(threads: Option<usize>) -> Result<rayon::ThreadPool> {
    let mut builder = rayon::ThreadPoolBuilder::new();
    if let Some(n) = threads {
        builder = builder.num_threads(n);
    }
    builder.build().context("не вдалося створити пул потоків")
}

fn default_output_dir(file: &Path) -> PathBuf {
    let mut name = file.file_name().unwrap_or(OsStr::new("output")).to_os_string();
    name.push("_extracted");
    file.with_file_name(name)
}
