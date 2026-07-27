//! Персистентні налаштування застосунку: `~/.GreatExtractor/config.yaml`.
//! Формат навмисно мінімальний (поки лише обрана тема TUI) і толерантний до
//! відсутнього/пошкодженого файлу — конфіг це лише зручність, а не
//! критичний для роботи стан, тож будь-яка помилка читання тихо
//! відкочується до значень за замовчуванням, а не падає застосунок.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Ключ обраної теми TUI (напр. `"standard"`, `"midnight_commander"`).
    pub theme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self { theme: "standard".to_string() }
    }
}

/// Шлях до файлу конфігурації: `~/.GreatExtractor/config.yaml`. `None`,
/// якщо домашню директорію визначити не вдалося (наприклад, середовище без
/// `HOME`/`USERPROFILE`).
pub fn default_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".GreatExtractor").join("config.yaml"))
}

/// Завантажує конфіг із заданого шляху; відсутній файл, брак прав чи
/// зіпсований YAML однаково повертають значення за замовчуванням.
pub fn load_from(path: &Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_yaml::from_str(&contents).ok())
        .unwrap_or_default()
}

/// Зберігає конфіг за заданим шляхом, створюючи батьківську директорію за
/// потреби.
pub fn save_to(path: &Path, config: &Config) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("не вдалося створити директорію {}", dir.display()))?;
    }
    let yaml = serde_yaml::to_string(config).context("не вдалося серіалізувати конфіг у YAML")?;
    std::fs::write(path, yaml).with_context(|| format!("не вдалося записати конфіг {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("great_extractor_config_test_{name}_{}.yaml", std::process::id()))
    }

    #[test]
    fn default_path_points_at_dot_great_extractor_config_yaml() {
        let Some(path) = default_path() else { return };
        assert!(path.ends_with(".GreatExtractor/config.yaml"));
    }

    #[test]
    fn load_from_missing_file_returns_default() {
        let path = temp_config_path("missing");
        let _ = std::fs::remove_file(&path);

        assert_eq!(load_from(&path), Config::default());
    }

    #[test]
    fn save_then_load_round_trips_theme() {
        let path = temp_config_path("roundtrip");
        let config = Config { theme: "dark".to_string() };

        save_to(&path, &config).expect("save_to має спрацювати у тимчасовій директорії");
        assert_eq!(load_from(&path), config);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_corrupted_file_returns_default() {
        let path = temp_config_path("corrupted");
        std::fs::write(&path, "{ not valid yaml [").expect("запис тимчасового файлу");

        assert_eq!(load_from(&path), Config::default());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_to_creates_missing_parent_directory() {
        let dir = std::env::temp_dir().join(format!("great_extractor_config_test_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("config.yaml");
        let config = Config { theme: "monochrome".to_string() };

        save_to(&path, &config).expect("save_to має створити відсутні директорії");
        assert_eq!(load_from(&path), config);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
