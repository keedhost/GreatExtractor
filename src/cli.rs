use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::about;

#[derive(Parser)]
#[command(name = about::BIN_NAME, about = about::SHORT_ABOUT, long_about = about::LONG_ABOUT)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Показати перелік усіх підтримуваних форматів (назва + опис) і вийти.
    #[arg(short = 'f', long = "formats", global = true)]
    pub formats: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Сканувати файл і вивести список знайдених вбудованих файлів.
    Scan {
        /// Шлях до файлу для сканування.
        file: PathBuf,

        /// Формат виводу.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,

        /// Показувати лише знахідки з впевненістю не нижче N (0-100).
        /// За замовчуванням відсікає знахідки без жодної структурної
        /// перевірки (евристичний фолбек, 40%) — на щільних бінарних файлах
        /// такі "збіги" на слабкі сигнатури (2-4 байти) інакше заповнюють
        /// вивід хибними спрацюваннями. `--min-confidence 0` показує все.
        #[arg(long, default_value_t = 41)]
        min_confidence: u8,

        /// Кількість потоків для сканування (за замовчуванням — кількість ядер CPU).
        #[arg(long)]
        threads: Option<usize>,

        /// Додати до списку знахідок ділянки з високою ентропією (`high_entropy_region`).
        #[arg(long)]
        entropy: bool,

        /// Розмір блоку (у байтах) для аналізу ентропії.
        #[arg(long, default_value_t = crate::entropy::DEFAULT_WINDOW)]
        entropy_window: usize,

        /// Порогове значення ентропії (0.0-8.0 біт/байт), вище якого блок вважається "підозрілим".
        #[arg(long, default_value_t = crate::entropy::DEFAULT_THRESHOLD)]
        entropy_threshold: f64,
    },

    /// Розкласти файл на окремі фрагменти за знайденими сигнатурами (raw carve).
    Extract {
        /// Шлях до файлу для екстракції.
        file: PathBuf,

        /// Директорія для витягнутих файлів (за замовчуванням — `<file>_extracted` поряд із вхідним файлом).
        #[arg(long)]
        output: Option<PathBuf>,

        /// Мінімальна впевненість (0-100) для екстракції знахідки. Той самий
        /// сенс, що й у `scan` — без цього фільтра екстракція намагалася б
        /// зберегти кожен хибний збіг на слабку сигнатуру як окремий файл.
        #[arg(long, default_value_t = 41)]
        min_confidence: u8,

        /// Не рекурсивно скановувати вже витягнуті фрагменти на вкладені знахідки.
        #[arg(long)]
        no_recursive: bool,

        /// Максимальна глибина рекурсивної екстракції.
        #[arg(long, default_value_t = 8)]
        max_depth: u32,

        /// Максимальна загальна кількість витягнутих файлів (захист від вибухового розростання).
        #[arg(long, default_value_t = 10_000)]
        max_files: usize,

        /// Показати, що було б екстраговано, без запису на диск.
        #[arg(long)]
        dry_run: bool,

        /// Кількість потоків для сканування (за замовчуванням — кількість ядер CPU).
        #[arg(long)]
        threads: Option<usize>,
    },

    /// Обчислити ентропію Шеннона по ковзних блоках файлу.
    Entropy {
        /// Шлях до файлу для аналізу.
        file: PathBuf,

        /// Розмір блоку (у байтах) для аналізу ентропії.
        #[arg(long, default_value_t = crate::entropy::DEFAULT_WINDOW)]
        window: usize,

        /// Порогове значення ентропії (0.0-8.0 біт/байт), вище якого блок вважається "підозрілим".
        #[arg(long, default_value_t = crate::entropy::DEFAULT_THRESHOLD)]
        threshold: f64,

        /// Формат виводу.
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },

    /// Інтерактивний перегляд: список знахідок, hex-вʼю, вибіркова екстракція, підсвітка ентропії.
    Tui {
        /// Шлях до файлу для перегляду.
        file: PathBuf,

        /// Директорія для вибірково витягнутих файлів (за замовчуванням — `<file>_extracted` поряд із вхідним файлом).
        #[arg(long)]
        output: Option<PathBuf>,

        /// Показувати лише знахідки з впевненістю не нижче N (0-100). Той
        /// самий сенс, що й у `scan`/`extract`.
        #[arg(long, default_value_t = 41)]
        min_confidence: u8,
    },
}

#[derive(Copy, Clone, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_flag_parses_long_and_short_without_subcommand() {
        let cli = Cli::try_parse_from(["greatie", "--formats"]).expect("--formats має парситись");
        assert!(cli.formats);
        assert!(cli.command.is_none());

        let cli = Cli::try_parse_from(["greatie", "-f"]).expect("-f має парситись");
        assert!(cli.formats);
        assert!(cli.command.is_none());
    }

    #[test]
    fn no_arguments_yields_no_command_and_formats_false() {
        let cli = Cli::try_parse_from(["greatie"]).expect("без аргументів теж має парситись");
        assert!(!cli.formats);
        assert!(cli.command.is_none());
    }

    #[test]
    fn formats_flag_combines_with_a_subcommand() {
        let cli = Cli::try_parse_from(["greatie", "scan", "some.bin", "--formats"])
            .expect("--formats — глобальний флаг, має парситись і після підкоманди");
        assert!(cli.formats);
        assert!(cli.command.is_some());
    }
}
