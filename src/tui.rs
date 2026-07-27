//! Інтерактивний TUI-режим (`great-extractor tui <file>`): навігація по списку
//! знахідок, hex-перегляд вибраної ділянки, вибіркова екстракція окремих
//! записів, підсвітка ентропійних зон.

use std::io::{self, Cursor};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect, Size};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use ratatui_image::picker::Picker;
use ratatui_image::{Image as ImageWidget, Resize};

use crate::about;
use crate::config;
use crate::entropy::{self, EntropyBlock};
use crate::scanner::{self, Finding};
use crate::signature;
use crate::validators;

const BYTES_PER_ROW: usize = 16;

#[derive(PartialEq, Eq)]
enum Focus {
    List,
    Hex,
}

/// Спливаюче меню фільтрів, відкрите поверх лівої панелі. `cursor` — індекс
/// підсвіченого варіанта; `ConfidenceInput` — режим ручного вводу відсотка.
enum Menu {
    Format { cursor: usize },
    Confidence { cursor: usize },
    ConfidenceInput { buffer: String },
    /// Довідка (`?`) з переліком УСІХ підтримуваних форматів — на відміну
    /// від `Format`, що показує лише формати, знайдені в поточному файлі.
    FormatsHelp { scroll: u16 },
    /// Меню вибору теми оформлення (`t`), за зразком перемикача скінів у
    /// Midnight Commander.
    Theme { cursor: usize },
    /// Довідка про програму (`h`) — той самий текст, що й `--help` у CLI
    /// (`about::LONG_ABOUT`): принцип роботи, команди, ліцензія, автор.
    AppHelp { scroll: u16 },
}

/// Кількість пунктів меню "Мінімальний відсоток співпадіння": 55%/80%/95%,
/// ручне введення, скидання до значення зі скану.
const CONFIDENCE_MENU_LEN: usize = 5;

/// Набір тем оформлення — за зразком перемикача скінів (F9 → Appearance) у
/// Midnight Commander: кілька готових палітр, перемикання клавішею `t`.
/// `Standard` відтворює вигляд, який був у застосунку до появи тем, і саме
/// вона лишається типовою (`ThemeKind::default()`), щоб нічия звичка не
/// зламалась після оновлення.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ThemeKind {
    #[default]
    Standard,
    MidnightCommander,
    Dark,
    Monochrome,
}

impl ThemeKind {
    const ALL: [ThemeKind; 4] =
        [ThemeKind::Standard, ThemeKind::MidnightCommander, ThemeKind::Dark, ThemeKind::Monochrome];

    fn label(self) -> &'static str {
        match self {
            ThemeKind::Standard => "Типова (як було)",
            ThemeKind::MidnightCommander => "Midnight Commander",
            ThemeKind::Dark => "Темна",
            ThemeKind::Monochrome => "Монохромна",
        }
    }

    /// Ключ для збереження в `~/.GreatExtractor/config.yaml` — стабільний
    /// рядок, незалежний від порядку варіантів чи `label()`, що є суто
    /// відображуваним текстом і може змінюватись.
    fn config_key(self) -> &'static str {
        match self {
            ThemeKind::Standard => "standard",
            ThemeKind::MidnightCommander => "midnight_commander",
            ThemeKind::Dark => "dark",
            ThemeKind::Monochrome => "monochrome",
        }
    }

    fn from_config_key(key: &str) -> Option<ThemeKind> {
        ThemeKind::ALL.into_iter().find(|k| k.config_key() == key)
    }

    /// Конкретні стилі теми. `Standard` навмисно дослівно повторює кольори,
    /// що раніше були захардкоджені по всьому файлу (`Color::Cyan` для
    /// фокусу, `Color::Red` для ентропії, `REVERSED` для виділення) — щоб
    /// вигляд за замовчуванням не змінився.
    fn palette(self) -> Theme {
        match self {
            ThemeKind::Standard => Theme {
                background: None,
                text: Style::default(),
                border: Style::default(),
                border_focused: Style::default().fg(Color::Cyan),
                selection: Style::default().add_modifier(Modifier::REVERSED),
                high_entropy: Style::default().fg(Color::Red),
                status_bar: Style::default(),
            },
            ThemeKind::MidnightCommander => Theme {
                background: Some(Color::Blue),
                text: Style::default().fg(Color::White).bg(Color::Blue),
                border: Style::default().fg(Color::White).bg(Color::Blue),
                border_focused: Style::default().fg(Color::Yellow).bg(Color::Blue).add_modifier(Modifier::BOLD),
                selection: Style::default().fg(Color::Black).bg(Color::Cyan),
                high_entropy: Style::default().fg(Color::LightRed).bg(Color::Blue),
                status_bar: Style::default().fg(Color::Black).bg(Color::Cyan),
            },
            ThemeKind::Dark => Theme {
                background: Some(Color::Black),
                text: Style::default().fg(Color::Gray).bg(Color::Black),
                border: Style::default().fg(Color::DarkGray).bg(Color::Black),
                border_focused: Style::default().fg(Color::Green).bg(Color::Black),
                selection: Style::default().fg(Color::Black).bg(Color::Green),
                high_entropy: Style::default().fg(Color::LightRed).bg(Color::Black),
                status_bar: Style::default().fg(Color::Gray).bg(Color::Black),
            },
            ThemeKind::Monochrome => Theme {
                background: None,
                text: Style::default(),
                border: Style::default(),
                border_focused: Style::default().add_modifier(Modifier::BOLD),
                selection: Style::default().add_modifier(Modifier::REVERSED),
                high_entropy: Style::default().add_modifier(Modifier::UNDERLINED),
                status_bar: Style::default(),
            },
        }
    }
}

/// Розгорнута палітра стилів для поточного кадру — обчислюється з
/// `ThemeKind` один раз на виклик `draw`, а не зберігається в `App` напряму,
/// щоб зміна теми не вимагала синхронізації двох джерел істини.
#[derive(Clone, Copy)]
struct Theme {
    /// Колір тла всього екрана; `None` — не чіпати тло терміналу (як у
    /// `Standard`, де воно завжди було прозорим).
    background: Option<Color>,
    text: Style,
    border: Style,
    border_focused: Style,
    selection: Style,
    high_entropy: Style,
    status_bar: Style,
}

struct App<'a> {
    data: &'a [u8],
    findings: Vec<Finding>,
    /// Індекси в `findings`, що проходять поточні фільтри (формат + мін.%) —
    /// саме за ними будується список та навігація, а не за `findings`
    /// напряму, щоб не копіювати самі знахідки при кожній зміні фільтра.
    filtered: Vec<usize>,
    /// Відсортований і дедуплікований перелік форматів, знайдених у файлі —
    /// джерело варіантів для меню "Формат".
    available_formats: Vec<String>,
    format_filter: Option<String>,
    confidence_filter: u8,
    /// Значення `--min-confidence`, з яким виконувалося сканування: нижче
    /// нього знахідок просто немає в пам'яті, тож саме до цього значення
    /// (а не до 0) скидається фільтр за впевненістю.
    initial_min_confidence: u8,
    /// Активна тема оформлення; `ThemeKind::default()` (`Standard`) зберігає
    /// вигляд, який був у застосунку до появи тем.
    theme: ThemeKind,
    /// Шлях до `config.yaml`, за яким зберігається вибір теми — `None` у
    /// юніт-тестах (щоб вони не чіпали реальну домашню директорію) і
    /// `Some(...)` у продуктивному `run()`, де конфіг реально читається й
    /// пишеться.
    config_path: Option<PathBuf>,
    menu: Option<Menu>,
    list_state: ListState,
    focus: Focus,
    hex_scroll: usize,
    entropy_blocks: Option<Vec<EntropyBlock>>,
    status: String,
    output_dir: PathBuf,
    /// Halfblocks за замовчуванням — миттєвий, без I/O; `run()` підмінює
    /// його на результат реального запиту можливостей терміналу вже після
    /// входу в alternate screen (щоб не сповільнювати юніт-тести, які
    /// створюють `App` поза реальним терміналом).
    picker: Picker,
}

impl<'a> App<'a> {
    fn new(data: &'a [u8], findings: Vec<Finding>, output_dir: PathBuf, min_confidence: u8) -> Self {
        let mut available_formats: Vec<String> = findings.iter().map(|f| f.format.clone()).collect();
        available_formats.sort();
        available_formats.dedup();

        let mut app = Self {
            data,
            findings,
            filtered: Vec::new(),
            available_formats,
            format_filter: None,
            confidence_filter: min_confidence,
            initial_min_confidence: min_confidence,
            theme: ThemeKind::default(),
            config_path: None,
            menu: None,
            list_state: ListState::default(),
            focus: Focus::List,
            hex_scroll: 0,
            entropy_blocks: None,
            status: default_status(),
            output_dir,
            picker: Picker::halfblocks(),
        };
        app.recompute_filtered();
        app
    }

    /// Перебудовує `filtered` під поточні `format_filter`/`confidence_filter`
    /// і утримує виділення в межах нового списку (замість того, щоб скидати
    /// його на початок при кожній зміні фільтра).
    fn recompute_filtered(&mut self) {
        let filtered: Vec<usize> = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| f.confidence >= self.confidence_filter)
            .filter(|(_, f)| match &self.format_filter {
                None => true,
                Some(fmt) => &f.format == fmt,
            })
            .map(|(i, _)| i)
            .collect();
        self.filtered = filtered;

        if self.filtered.is_empty() {
            self.list_state.select(None);
        } else {
            let current = self.list_state.selected().unwrap_or(0);
            self.list_state.select(Some(current.min(self.filtered.len() - 1)));
        }
        self.hex_scroll = 0;
    }

    fn open_format_menu(&mut self) {
        let cursor = match &self.format_filter {
            None => 0,
            Some(fmt) => self.available_formats.iter().position(|f| f == fmt).map_or(0, |i| i + 1),
        };
        self.menu = Some(Menu::Format { cursor });
    }

    fn open_confidence_menu(&mut self) {
        self.menu = Some(Menu::Confidence { cursor: 0 });
    }

    fn open_formats_help(&mut self) {
        self.menu = Some(Menu::FormatsHelp { scroll: 0 });
    }

    fn open_app_help(&mut self) {
        self.menu = Some(Menu::AppHelp { scroll: 0 });
    }

    /// Скидає одноразове сповіщення в статус-барі (зміна теми/фільтра,
    /// результат екстракції тощо) назад до підказок гарячих клавіш.
    /// Викликається перед обробкою кожної нової клавіші (`event_loop`), щоб
    /// таке сповіщення не витісняло підказки назавжди.
    fn clear_transient_status(&mut self) {
        self.status = default_status();
    }

    fn open_theme_menu(&mut self) {
        let cursor = ThemeKind::ALL.iter().position(|&k| k == self.theme).unwrap_or(0);
        self.menu = Some(Menu::Theme { cursor });
    }

    /// Розгортає активний `ThemeKind` у конкретні стилі для поточного кадру.
    fn palette(&self) -> Theme {
        self.theme.palette()
    }

    fn reset_filters(&mut self) {
        self.format_filter = None;
        self.confidence_filter = self.initial_min_confidence;
        self.status = "Фільтри скинуто".to_string();
        self.recompute_filtered();
    }

    fn apply_confidence_filter(&mut self, value: u8) {
        self.confidence_filter = value;
        self.menu = None;
        self.status = format!("Мінімальна впевненість: {value}%");
        self.recompute_filtered();
    }

    /// Обробляє клавішу, коли відкрито спливаюче меню фільтрів; звичайна
    /// навігація списком/hex у цей час заблокована (див. `event_loop`).
    fn handle_menu_key(&mut self, code: KeyCode) {
        match self.menu.take() {
            Some(Menu::Format { mut cursor }) => {
                let len = self.available_formats.len() + 1;
                match code {
                    KeyCode::Esc => {}
                    KeyCode::Up | KeyCode::Char('k') => {
                        cursor = cursor.saturating_sub(1);
                        self.menu = Some(Menu::Format { cursor });
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        cursor = (cursor + 1).min(len - 1);
                        self.menu = Some(Menu::Format { cursor });
                    }
                    KeyCode::Enter => {
                        self.format_filter = if cursor == 0 {
                            None
                        } else {
                            Some(self.available_formats[cursor - 1].clone())
                        };
                        self.status = format!("Фільтр формату: {}", self.format_filter.as_deref().unwrap_or("усі"));
                        self.recompute_filtered();
                    }
                    _ => self.menu = Some(Menu::Format { cursor }),
                }
            }
            Some(Menu::Confidence { mut cursor }) => match code {
                KeyCode::Esc => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.menu = Some(Menu::Confidence { cursor });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    cursor = (cursor + 1).min(CONFIDENCE_MENU_LEN - 1);
                    self.menu = Some(Menu::Confidence { cursor });
                }
                KeyCode::Enter => match cursor {
                    0 => self.apply_confidence_filter(55),
                    1 => self.apply_confidence_filter(80),
                    2 => self.apply_confidence_filter(95),
                    3 => self.menu = Some(Menu::ConfidenceInput { buffer: String::new() }),
                    _ => self.apply_confidence_filter(self.initial_min_confidence),
                },
                _ => self.menu = Some(Menu::Confidence { cursor }),
            },
            Some(Menu::ConfidenceInput { mut buffer }) => match code {
                KeyCode::Esc => {}
                KeyCode::Backspace => {
                    buffer.pop();
                    self.menu = Some(Menu::ConfidenceInput { buffer });
                }
                KeyCode::Char(c) if c.is_ascii_digit() && buffer.len() < 3 => {
                    buffer.push(c);
                    self.menu = Some(Menu::ConfidenceInput { buffer });
                }
                KeyCode::Enter => {
                    if let Ok(value) = buffer.parse::<u32>() {
                        self.apply_confidence_filter(value.min(100) as u8);
                    }
                }
                _ => self.menu = Some(Menu::ConfidenceInput { buffer }),
            },
            Some(Menu::FormatsHelp { scroll }) => match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | '?') => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    self.menu = Some(Menu::FormatsHelp { scroll: scroll.saturating_sub(1) });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.menu = Some(Menu::FormatsHelp { scroll: scroll.saturating_add(1) });
                }
                KeyCode::PageUp => {
                    self.menu = Some(Menu::FormatsHelp { scroll: scroll.saturating_sub(10) });
                }
                KeyCode::PageDown => {
                    self.menu = Some(Menu::FormatsHelp { scroll: scroll.saturating_add(10) });
                }
                _ => self.menu = Some(Menu::FormatsHelp { scroll }),
            },
            Some(Menu::Theme { mut cursor }) => match code {
                KeyCode::Esc => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.menu = Some(Menu::Theme { cursor });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    cursor = (cursor + 1).min(ThemeKind::ALL.len() - 1);
                    self.menu = Some(Menu::Theme { cursor });
                }
                KeyCode::Enter => {
                    self.theme = ThemeKind::ALL[cursor];
                    self.status = format!("Тема: {}", self.theme.label());
                    if let Some(path) = &self.config_path {
                        let cfg = config::Config { theme: self.theme.config_key().to_string() };
                        if let Err(err) = config::save_to(path, &cfg) {
                            self.status = format!("Тема: {} (не вдалося зберегти конфіг: {err})", self.theme.label());
                        }
                    }
                }
                _ => self.menu = Some(Menu::Theme { cursor }),
            },
            Some(Menu::AppHelp { scroll }) => match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | 'h') => {}
                KeyCode::Up | KeyCode::Char('k') => {
                    self.menu = Some(Menu::AppHelp { scroll: scroll.saturating_sub(1) });
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.menu = Some(Menu::AppHelp { scroll: scroll.saturating_add(1) });
                }
                KeyCode::PageUp => {
                    self.menu = Some(Menu::AppHelp { scroll: scroll.saturating_sub(10) });
                }
                KeyCode::PageDown => {
                    self.menu = Some(Menu::AppHelp { scroll: scroll.saturating_add(10) });
                }
                _ => self.menu = Some(Menu::AppHelp { scroll }),
            },
            None => {}
        }
    }

    fn selected(&self) -> Option<&Finding> {
        let selected_idx = self.list_state.selected()?;
        let idx = *self.filtered.get(selected_idx)?;
        self.findings.get(idx)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len() as isize;
        let current = self.list_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len - 1);
        self.list_state.select(Some(next as usize));
        self.hex_scroll = 0;
    }

    /// Гортає вміст правої панелі під інформаційним блоком: рядки hex-дампу
    /// для звичайних знахідок, записи каталогу для архівних форматів, або
    /// рядки тексту для текстових форматів (те саме поле `hex_scroll`, бо в
    /// кожен момент часу видно лише одне).
    fn scroll_hex(&mut self, delta: isize) {
        let Some(finding) = self.selected() else { return };
        let Some(fragment) = self.data.get(finding.offset_start..=finding.offset_end) else { return };
        let total_rows = if is_archive_format(&finding.format) {
            validators::list_archive_entries(&finding.format, fragment).map_or(0, |entries| entries.len())
        } else if is_text_format(&finding.format) {
            decode_as_text(fragment).lines().count()
        } else {
            finding.size.div_ceil(BYTES_PER_ROW)
        };
        let next = (self.hex_scroll as isize + delta).clamp(0, total_rows.saturating_sub(1) as isize);
        self.hex_scroll = next as usize;
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::Hex,
            Focus::Hex => Focus::List,
        };
    }

    fn toggle_entropy(&mut self) {
        if self.entropy_blocks.is_some() {
            self.entropy_blocks = None;
            self.status = default_status();
        } else {
            self.entropy_blocks = Some(entropy::compute(self.data, entropy::DEFAULT_WINDOW, entropy::DEFAULT_THRESHOLD));
            self.status = "Підсвітка ентропії: ділянки з високою ентропією позначені ★".to_string();
        }
    }

    /// Чи перетинається знахідка з якимось високоентропійним блоком.
    fn is_high_entropy(&self, finding: &Finding) -> bool {
        let Some(blocks) = &self.entropy_blocks else { return false };
        blocks
            .iter()
            .any(|b| b.high && b.offset < finding.offset_end + 1 && b.offset + b.size > finding.offset_start)
    }

    fn extract_selected(&mut self) {
        let Some(finding) = self.selected().cloned() else { return };
        match extract_single(self.data, &finding, &self.output_dir) {
            Ok(path) => self.status = format!("Витягнуто: {}", path.display()),
            Err(err) => self.status = format!("Помилка екстракції: {err}"),
        }
    }
}

fn default_status() -> String {
    "↑/↓ — навігація  Tab — фокус  f — формат  c — мін.%  r — скинути фільтри  e — ентропія  x — екстракція  t — тема  ? — усі формати  h — про програму  q — вихід"
        .to_string()
}

/// Нормалізує символьні клавіші під українську розкладку клавіатури: якщо
/// натиснута літера сидить на тій самій фізичній клавіші, що й англійська
/// літера гарячої клавіші (напр. `f`/`а`, `t`/`е`), обидва варіанти
/// трактуються однаково. Підказки в статус-барі (`default_status`) свідомо
/// лишаються англійськими — це суто внутрішня нормалізація вводу, а не
/// переклад інтерфейсу. Розкладка стандартна українська (ЙЦУКЕН); символи
/// поза цією таблицею (включно з цифрами) повертаються без змін.
fn normalize_key_code(code: KeyCode) -> KeyCode {
    match code {
        KeyCode::Char(c) => KeyCode::Char(normalize_ukrainian_layout_char(c)),
        other => other,
    }
}

fn normalize_ukrainian_layout_char(c: char) -> char {
    match c {
        'й' => 'q',
        'ц' => 'w',
        'у' => 'e',
        'к' => 'r',
        'е' => 't',
        'н' => 'y',
        'г' => 'u',
        'ш' => 'i',
        'щ' => 'o',
        'з' => 'p',
        'ф' => 'a',
        'і' => 's',
        'в' => 'd',
        'а' => 'f',
        'п' => 'g',
        'р' => 'h',
        'о' => 'j',
        'л' => 'k',
        'д' => 'l',
        'я' => 'z',
        'ч' => 'x',
        'с' => 'c',
        'м' => 'v',
        'и' => 'b',
        'т' => 'n',
        'ь' => 'm',
        other => other,
    }
}

/// Записує один вибраний фрагмент на диск за тією ж схемою іменування, що
/// й пакетна екстракція (`extractor.rs`), але без рекурсії — лише цей
/// конкретний запис.
fn extract_single(data: &[u8], finding: &Finding, output_dir: &Path) -> Result<PathBuf> {
    let extension = signature::extension_for(&finding.format);
    let file_name = format!(
        "{:08x}_{}.{}",
        finding.offset_start,
        finding.format.to_lowercase(),
        extension
    );
    let out_path = output_dir.join(&file_name);
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("не вдалося створити директорію {}", output_dir.display()))?;
    std::fs::write(&out_path, &data[finding.offset_start..=finding.offset_end])
        .with_context(|| format!("не вдалося записати файл {}", out_path.display()))?;
    Ok(out_path)
}

/// Запускає TUI: сканує файл, ініціалізує термінал, виконує цикл подій,
/// відновлює термінал перед виходом (у т.ч. при panic — через RAII-скидання
/// `ratatui::restore` в `run`).
pub fn run(file: &Path, output_dir: PathBuf, data: &[u8], min_confidence: u8) -> Result<()> {
    let findings: Vec<_> = scanner::scan_quiet(data)
        .into_iter()
        .filter(|f| f.confidence >= min_confidence)
        .collect();
    let mut app = App::new(data, findings, output_dir, min_confidence);

    if let Some(path) = config::default_path() {
        let cfg = config::load_from(&path);
        if let Some(theme) = ThemeKind::from_config_key(&cfg.theme) {
            app.theme = theme;
        }
        app.config_path = Some(path);
    }

    ratatui::run(|terminal| {
        // Запит можливостей терміналу (Sixel/Kitty/iTerm2/halfblocks-фолбек)
        // має відбутися після входу в alternate screen, але до першого
        // читання подій — саме тут, а не в `App::new`.
        app.picker = Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks());
        event_loop(terminal, &mut app)
    })
    .with_context(|| format!("помилка TUI під час перегляду {}", file.display()))
}

/// Чи можна показати знахідку цього формату як растрове зображення (у
/// доповнення до hex-перегляду), а не лише як hex.
fn is_image_format(format: &str) -> bool {
    matches!(
        format,
        "PNG" | "JPEG" | "GIF87a" | "GIF89a" | "BMP" | "ICO" | "CUR" | "TIFF-LE" | "TIFF-BE" | "WEBP"
    )
}

/// Заголовок панелі структурного перелічення для цього формату, якщо він
/// підтримується (`validators::list_archive_entries` поверне для нього не
/// `None`) — інакше показується лише hex. Охоплює не тільки "справжні"
/// архіви з файлами, а й будь-яку іншу внутрішню структуру запис-за-записом:
/// таблиці шрифтів, чанки PNG/RIFF/IFF, бокси ISOBMFF, секції виконуваних
/// файлів.
fn structure_panel_title(format: &str) -> Option<&'static str> {
    match format {
        "ZIP" | "TAR" | "CPIO-newc" | "CPIO-crc" | "CPIO-odc" | "AR" | "WAD-I" | "WAD-P" | "PAK-Quake" | "VPK"
        | "RAR" => Some(" Файли в архіві "),
        "TTF" | "OTF" => Some(" Таблиці шрифту "),
        "PNG" | "MNG" | "JNG" | "WAV" | "AVI" | "WEBP" | "CDR" | "ANI" | "RMID" | "RIFF-PAL" | "RDIB"
        | "AIFF" | "AIFC" | "8SVX" | "ILBM" | "ANIM" | "ANBM" => Some(" Чанки "),
        "MP4-isom" | "MP4-mp42" | "MP4-mp41" | "MP4-avc1" | "MP4-iso2" | "MOV" | "M4A" | "M4B" | "M4P" | "3GP"
        | "3G2" | "3GP-3gp5" | "M4V" | "HEIC" | "HEIC-10bit" | "AVIF" | "AVIF-sequence" | "HEIF-mif1"
        | "HEIF-msf1" | "HEIF-heis" | "HEIF-hevc" | "JP2" | "JXL" => Some(" Бокси "),
        "ELF" | "PE" | "Mach-O-32-BE" | "Mach-O-32-LE" | "Mach-O-64-BE" | "Mach-O-64-LE" => Some(" Секції "),
        "Mach-O-Fat" => Some(" Архітектури "),
        "SQLite" => Some(" Схема бази "),
        "ISO9660" => Some(" Файли (корінь) "),
        _ => None,
    }
}

/// Чи можна показати знахідку цього формату як структурний перелік (у
/// доповнення до hex-перегляду) замість/поряд із самим лише hex.
fn is_archive_format(format: &str) -> bool {
    structure_panel_title(format).is_some()
}

/// Чи є цей формат по суті текстовим — тоді замість hex-дампу показуємо
/// самі байти як текст (це і є їхній "природний" вигляд, на відміну від
/// растрових/архівних форматів).
fn is_text_format(format: &str) -> bool {
    matches!(
        format,
        "SVG" | "XPM" | "EPS" | "XFig" | "PGP-Message" | "PGP-PublicKey" | "PGP-PrivateKey" | "PGP-Signature"
            | "PEM" | "REG4" | "REG5" | "MBOX" | "WebVTT" | "ASS" | "BDF" | "FDF"
    )
}

/// Декодує фрагмент як текст: розпізнає BOM UTF-16LE (типово для `.reg`-файлів,
/// експортованих сучасним regedit) і UTF-8, інакше декодує як UTF-8 з заміною
/// некоректних послідовностей — це відповідає "природному" вигляду знахідки
/// краще за hex, навіть якщо окремі байти не є дійсним текстом.
fn decode_as_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            app.clear_transient_status();
            let code = normalize_key_code(key.code);
            if app.menu.is_some() {
                app.handle_menu_key(code);
                continue;
            }
            match code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Tab => app.toggle_focus(),
                KeyCode::Char('e') => app.toggle_entropy(),
                KeyCode::Char('x') => app.extract_selected(),
                KeyCode::Char('f') => app.open_format_menu(),
                KeyCode::Char('c') => app.open_confidence_menu(),
                KeyCode::Char('r') => app.reset_filters(),
                KeyCode::Char('t') => app.open_theme_menu(),
                KeyCode::Char('?') => app.open_formats_help(),
                KeyCode::Char('h') => app.open_app_help(),
                KeyCode::Down | KeyCode::Char('j') => match app.focus {
                    Focus::List => app.move_selection(1),
                    Focus::Hex => app.scroll_hex(1),
                },
                KeyCode::Up | KeyCode::Char('k') => match app.focus {
                    Focus::List => app.move_selection(-1),
                    Focus::Hex => app.scroll_hex(-1),
                },
                KeyCode::PageDown => app.scroll_hex(16),
                KeyCode::PageUp => app.scroll_hex(-16),
                _ => {}
            }
        }
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let theme = app.palette();
    if let Some(bg) = theme.background {
        frame.render_widget(Block::default().style(Style::default().bg(bg)), frame.area());
    }

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(root[0]);

    draw_findings_list(frame, panels[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(format_info_height(app)), Constraint::Min(0)])
        .split(panels[1]);
    draw_format_info(frame, right[0], app);

    let selected_format = app.selected().map(|f| f.format.clone());
    let show_image = selected_format.as_deref().is_some_and(is_image_format);
    let show_archive = selected_format.as_deref().is_some_and(is_archive_format);
    let show_text = selected_format.as_deref().is_some_and(is_text_format);
    if show_image || show_archive {
        let content = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(right[1]);
        if show_image {
            draw_image_preview(frame, content[0], app);
        } else {
            draw_archive_list(frame, content[0], app);
        }
        draw_hex_view(frame, content[1], app);
    } else if show_text {
        // Текст замінює hex цілком — це і є "природний" вигляд знахідки,
        // а не додаткова панель поряд, як для зображень/архівів.
        draw_text_view(frame, right[1], app);
    } else {
        draw_hex_view(frame, right[1], app);
    }

    draw_status_bar(frame, root[1], app);

    draw_menu_popup(frame, app);
}

/// Показує спливаюче меню фільтра (формат/мінімальний %) поверх усього
/// іншого вмісту екрана, якщо воно зараз відкрите.
fn draw_menu_popup(frame: &mut Frame, app: &App) {
    let Some(menu) = &app.menu else { return };
    let area = frame.area();
    let theme = app.palette();

    match menu {
        Menu::Format { cursor } => {
            let mut options = vec!["Усі формати".to_string()];
            options.extend(app.available_formats.iter().cloned());
            draw_selection_popup(frame, area, " Формат ", &options, *cursor, theme);
        }
        Menu::Confidence { cursor } => {
            let options = vec![
                "55%".to_string(),
                "80%".to_string(),
                "95%".to_string(),
                "Власне значення...".to_string(),
                format!("Скинути (мін. зі скану: {}%)", app.initial_min_confidence),
            ];
            draw_selection_popup(frame, area, " Мінімальний відсоток співпадіння ", &options, *cursor, theme);
        }
        Menu::ConfidenceInput { buffer } => {
            let popup_area = centered_rect(30, 3, area);
            frame.render_widget(Clear, popup_area);
            let block = Block::default()
                .borders(Borders::ALL)
                .title(styled_title(" Мін. % (0-100), Enter — підтвердити ", theme))
                .style(theme.text)
                .border_style(theme.border);
            frame.render_widget(Paragraph::new(format!("{buffer}_")).block(block), popup_area);
        }
        Menu::FormatsHelp { scroll } => draw_formats_help_popup(frame, area, *scroll, theme),
        Menu::Theme { cursor } => {
            let options: Vec<String> = ThemeKind::ALL.iter().map(|k| k.label().to_string()).collect();
            draw_selection_popup(frame, area, " Тема ", &options, *cursor, theme);
        }
        Menu::AppHelp { scroll } => draw_app_help_popup(frame, area, *scroll, theme),
    }
}

/// Довідкове спливаюче вікно (клавіша `h`) із тим самим текстом, що й
/// `--help` у CLI (`about::LONG_ABOUT`) — принцип роботи, команди, ліцензія,
/// автор. Один спільний текст для обох місць показу, щоб опис не розходився.
fn draw_app_help_popup(frame: &mut Frame, area: Rect, scroll: u16, theme: Theme) {
    let popup_area = centered_rect(80, (area.height * 80 / 100).max(10), area);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(styled_title(" Про програму (Esc — закрити, ↑/↓/PgUp/PgDn — гортати) ", theme))
        .style(theme.text)
        .border_style(theme.border);
    frame.render_widget(
        Paragraph::new(about::LONG_ABOUT).wrap(Wrap { trim: true }).block(block).scroll((scroll, 0)),
        popup_area,
    );
}

/// Довідкове спливаюче вікно (клавіша `?`) з переліком УСІХ підтримуваних
/// форматів і їх описів — на відміну від меню "Формат" (`f`), що показує
/// лише формати, знайдені в поточному файлі. Той самий `signature::usage_note`,
/// що й панель "Про формат", тож опис одного формату завжди однаковий всюди.
fn draw_formats_help_popup(frame: &mut Frame, area: Rect, scroll: u16, theme: Theme) {
    let formats = signature::all_formats();

    let mut text = format!("Підтримується {} форматів:\n\n", formats.len());
    for (name, note) in &formats {
        text.push_str(name);
        text.push('\n');
        text.push_str("  ");
        text.push_str(note);
        text.push_str("\n\n");
    }

    let popup_area = centered_rect(80, (area.height * 80 / 100).max(10), area);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(styled_title(" Усі підтримувані формати (Esc — закрити, ↑/↓/PgUp/PgDn — гортати) ", theme))
        .style(theme.text)
        .border_style(theme.border);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: true }).block(block).scroll((scroll, 0)),
        popup_area,
    );
}

/// Малює спливаючий список варіантів вибору (формат/пресет %/тема) із
/// підсвіченим поточним пунктом, по центру екрана, над усім іншим вмістом.
fn draw_selection_popup(frame: &mut Frame, area: Rect, title: &str, options: &[String], cursor: usize, theme: Theme) {
    let height = (options.len() as u16 + 2).clamp(3, area.height.saturating_sub(2).max(3));
    let popup_area = centered_rect(50, height, area);
    frame.render_widget(Clear, popup_area);

    let lines: Vec<Line> = options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            if i == cursor {
                Line::from(Span::styled(format!("▶ {opt}"), theme.selection))
            } else {
                Line::from(Span::styled(format!("  {opt}"), theme.text))
            }
        })
        .collect();

    let block = Block::default().borders(Borders::ALL).title(styled_title(title.to_string(), theme)).style(theme.text).border_style(theme.border);
    frame.render_widget(Paragraph::new(lines).block(block), popup_area);
}

/// Уніфікований вигляд заголовка панелі/спливаючого вікна — той самий
/// "виділений" стиль (`theme.selection`), що й у підсвіченого пункту списку
/// чи меню, застосований до тексту заголовка. Використовується всюди, де є
/// заголовки елементів (панелі знахідок, hex, про формат, фільтри,
/// спливаючі меню тощо), щоб вони виглядали однаково помітно.
fn styled_title(text: impl Into<String>, theme: Theme) -> Span<'static> {
    Span::styled(text.into(), theme.selection)
}

/// Прямокутник заданої ширини (у % від `area`) і фіксованої висоти, по
/// центру `area` — стандартний приклад для спливаючих вікон у ratatui.
fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let width = (area.width * percent_x / 100).min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect { x, y, width, height }
}

/// Базова висота панелі "Про формат" (2 рядки рамки + до ~3 рядків опису
/// формату, що вміщує більшість описів з `usage_note` при типовій ширині).
const FORMAT_INFO_BASE_HEIGHT: u16 = 5;

/// Скільки рядків має зайняти панель "Про формат" — базова висота плюс
/// рядки фактів (`format_facts`) з порожнім рядком-роздільником, якщо вони
/// є для вибраної знахідки.
fn format_info_height(app: &App) -> u16 {
    let Some(finding) = app.selected() else { return FORMAT_INFO_BASE_HEIGHT };
    let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end) else {
        return FORMAT_INFO_BASE_HEIGHT;
    };
    let extra = validators::format_facts(&finding.format, fragment)
        .map_or(0, |facts| facts.lines().count() as u16 + 1);
    FORMAT_INFO_BASE_HEIGHT + extra
}

/// Показує короткий довідковий опис вибраного формату (що це за файл, де і
/// ким він типово використовується), а за наявності — ще й кілька ключових
/// фактів із заголовка (тривалість, частота дискретизації, роздільність,
/// мапер ROM тощо), щоб не доводилось вичитувати їх із hex вручну.
fn draw_format_info(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let block = Block::default().borders(Borders::ALL).title(styled_title(" Про формат ", theme)).style(theme.text).border_style(theme.border);
    let Some(finding) = app.selected() else {
        frame.render_widget(Paragraph::new("Немає знахідок").block(block), area);
        return;
    };

    let mut text = signature::usage_note(&finding.format).to_string();
    if let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end)
        && let Some(facts) = validators::format_facts(&finding.format, fragment)
    {
        text.push_str("\n\n");
        text.push_str(&facts);
    }
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(block), area);
}

/// Без явних лімітів `image` crate за замовчуванням обмежує лише сумарну
/// алокацію декодера (512 MiB), але НЕ ширину/висоту зображення: маленький
/// на диску, але крафтований файл (величезні `width`/`height` при високому
/// ступені стиснення — класична "decompression bomb" для растрових
/// зображень) міг би на мить виділити до пів гігабайта пам'яті заради
/// текстового прев'ю розміром у кілька десятків символів. Ці межі — розумні
/// саме для термінального прев'ю, а не для повноцінного перегляду.
fn image_preview_limits() -> image::Limits {
    // `Limits` позначена `#[non_exhaustive]` — конструктор через літерал
    // структури недоступний ззовні крейта навіть із `..Default::default()`,
    // тож поля (вони публічні) виставляються окремо після побудови за
    // замовчуванням.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(64 * 1024 * 1024);
    limits
}

fn decode_image_for_preview(fragment: &[u8]) -> image::ImageResult<image::DynamicImage> {
    let mut reader = image::ImageReader::new(Cursor::new(fragment));
    reader.limits(image_preview_limits());
    reader.with_guessed_format()?.decode()
}

/// Показує вибрану знахідку як растрове зображення (Sixel/Kitty/iTerm2, або
/// halfblocks-фолбек, залежно від можливостей терміналу), декодуючи саме той
/// байтовий фрагмент, що й hex-перегляд нижче.
fn draw_image_preview(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let block = Block::default().borders(Borders::ALL).title(styled_title(" Зображення ", theme)).style(theme.text).border_style(theme.border);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(finding) = app.selected() else { return };
    let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end) else {
        return;
    };

    let message = match decode_image_for_preview(fragment) {
        Ok(dyn_img) => {
            match app
                .picker
                .new_protocol(dyn_img, Size::new(inner.width, inner.height), Resize::Fit(None))
            {
                Ok(protocol) => {
                    frame.render_widget(ImageWidget::new(&protocol), inner);
                    return;
                }
                Err(err) => format!("Не вдалося підготувати зображення для показу: {err}"),
            }
        }
        Err(err) => format!("Не вдалося декодувати зображення: {err}"),
    };
    frame.render_widget(Paragraph::new(message), inner);
}

/// Показує структурний перелік усередині знахідки (файли архіву, таблиці
/// шрифту, чанки, бокси чи секції — залежно від формату; ім'я + розмір),
/// прогорнутий тим самим `hex_scroll`, що й hex-перегляд нижче.
fn draw_archive_list(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let Some(finding) = app.selected() else { return };
    let title = structure_panel_title(&finding.format).unwrap_or(" Перелік ");
    let block = Block::default().borders(Borders::ALL).title(styled_title(title, theme)).style(theme.text).border_style(theme.border);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end) else {
        frame.render_widget(Paragraph::new("Не вдалося розібрати структуру цієї знахідки."), inner);
        return;
    };

    let message = match validators::list_archive_entries(&finding.format, fragment) {
        Some(entries) if !entries.is_empty() => {
            let visible_rows = inner.height as usize;
            let lines: Vec<Line> = entries
                .iter()
                .skip(app.hex_scroll)
                .take(visible_rows)
                .map(|e| Line::from(format!("{:>10}b  {}", e.size, e.name)))
                .collect();
            frame.render_widget(Paragraph::new(lines), inner);
            return;
        }
        Some(_) => "Немає записів для показу.".to_string(),
        None => "Не вдалося розібрати структуру цієї знахідки.".to_string(),
    };
    frame.render_widget(Paragraph::new(message), inner);
}

fn draw_findings_list(frame: &mut Frame, area: Rect, app: &App) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    draw_filter_bar(frame, sections[0], app);
    draw_findings_items(frame, sections[1], app);
}

/// Показує поточний стан фільтрів (формат, мінімальний % впевненості) і
/// підказки клавіш для їх зміни — постійно видимий "заголовок" лівої панелі.
fn draw_filter_bar(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let format_label = app.format_filter.as_deref().unwrap_or("усі");
    let text = format!(
        "Формат: {format_label}   Мін.%: {}%\n[f] формат  [c] мін.%  [r] скинути",
        app.confidence_filter
    );
    let block = Block::default().borders(Borders::ALL).title(styled_title(" Фільтри ", theme)).style(theme.text).border_style(theme.border);
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_findings_items(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|&i| {
            let f = &app.findings[i];
            let label = format!(
                "0x{:08x}  {:<14} {:>10}b  {:>3}%",
                f.offset_start, f.format, f.size, f.confidence
            );
            let style = if app.is_high_entropy(f) { theme.high_entropy } else { theme.text };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let border_style = if app.focus == Focus::List { theme.border_focused } else { theme.border };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(styled_title(format!(" Знахідки ({}/{}) ", app.filtered.len(), app.findings.len()), theme))
                .style(theme.text)
                .border_style(border_style),
        )
        .highlight_style(theme.selection)
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, &mut app.list_state.clone());
}

fn draw_hex_view(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let border_style = if app.focus == Focus::Hex { theme.border_focused } else { theme.border };

    let Some(finding) = app.selected() else {
        let block = Block::default().borders(Borders::ALL).title(styled_title(" Hex ", theme)).style(theme.text).border_style(border_style);
        frame.render_widget(Paragraph::new("Немає знахідок").block(block), area);
        return;
    };

    let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end) else {
        let block = Block::default().borders(Borders::ALL).title(styled_title(" Hex ", theme)).style(theme.text).border_style(border_style);
        frame.render_widget(Paragraph::new("Некоректний діапазон знахідки.").block(block), area);
        return;
    };
    let visible_rows = area.height.saturating_sub(2) as usize;
    let start_row = app.hex_scroll;

    let mut lines: Vec<Line> = Vec::with_capacity(visible_rows);
    for row in start_row..(start_row + visible_rows) {
        let row_start = row * BYTES_PER_ROW;
        if row_start >= fragment.len() {
            break;
        }
        let row_end = (row_start + BYTES_PER_ROW).min(fragment.len());
        let chunk = &fragment[row_start..row_end];

        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();

        lines.push(Line::from(format!(
            "{:08x}  {:<48}{}",
            finding.offset_start + row_start,
            hex,
            ascii
        )));
    }

    let title = format!(
        " Hex: {} [0x{:08x}-0x{:08x}] ",
        finding.format, finding.offset_start, finding.offset_end
    );
    let block = Block::default().borders(Borders::ALL).title(styled_title(title, theme)).style(theme.text).border_style(border_style);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Показує знахідку текстового формату як сам текст (замість hex) — це і є
/// "природний" вигляд SVG/PGP-ключа/субтитрів тощо. Скролиться тим самим
/// `hex_scroll`, що й hex/архівні перегляди.
fn draw_text_view(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    let border_style = if app.focus == Focus::Hex { theme.border_focused } else { theme.border };

    let Some(finding) = app.selected() else {
        let block = Block::default().borders(Borders::ALL).title(styled_title(" Текст ", theme)).style(theme.text).border_style(border_style);
        frame.render_widget(Paragraph::new("Немає знахідок").block(block), area);
        return;
    };

    let Some(fragment) = app.data.get(finding.offset_start..=finding.offset_end) else {
        let block = Block::default().borders(Borders::ALL).title(styled_title(" Текст ", theme)).style(theme.text).border_style(border_style);
        frame.render_widget(Paragraph::new("Некоректний діапазон знахідки.").block(block), area);
        return;
    };
    let text = decode_as_text(fragment);

    let title = format!(
        " Текст: {} [0x{:08x}-0x{:08x}] ",
        finding.format, finding.offset_start, finding.offset_end
    );
    let block = Block::default().borders(Borders::ALL).title(styled_title(title, theme)).style(theme.text).border_style(border_style);
    let scroll = app.hex_scroll.min(u16::MAX as usize) as u16;
    frame.render_widget(Paragraph::new(text).block(block).scroll((scroll, 0)), area);
}

fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.palette();
    frame.render_widget(Paragraph::new(app.status.as_str()).style(theme.status_bar), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(offset_start: usize, offset_end: usize, format: &str) -> Finding {
        finding_with_confidence(offset_start, offset_end, format, 90)
    }

    fn finding_with_confidence(offset_start: usize, offset_end: usize, format: &str, confidence: u8) -> Finding {
        Finding {
            format: format.to_string(),
            description: format.to_string(),
            offset_start,
            offset_end,
            size: offset_end - offset_start + 1,
            confidence,
            name: None,
        }
    }

    #[test]
    fn new_selects_first_finding_when_nonempty() {
        let data = vec![0u8; 100];
        let app = App::new(&data, vec![finding(0, 9, "A"), finding(10, 19, "B")], PathBuf::new(), 0);
        assert_eq!(app.list_state.selected(), Some(0));
    }

    #[test]
    fn new_selects_nothing_when_empty() {
        let data = vec![0u8; 10];
        let app = App::new(&data, vec![], PathBuf::new(), 0);
        assert_eq!(app.list_state.selected(), None);
    }

    #[test]
    fn move_selection_clamps_at_both_ends() {
        let data = vec![0u8; 100];
        let mut app = App::new(&data, vec![finding(0, 9, "A"), finding(10, 19, "B")], PathBuf::new(), 0);

        app.move_selection(-5); // вже на 0, не має піти в мінус
        assert_eq!(app.list_state.selected(), Some(0));

        app.move_selection(1);
        assert_eq!(app.list_state.selected(), Some(1));

        app.move_selection(5); // вже на останньому, не має вийти за межі
        assert_eq!(app.list_state.selected(), Some(1));
    }

    #[test]
    fn move_selection_resets_hex_scroll() {
        let data = vec![0u8; 100];
        let mut app = App::new(&data, vec![finding(0, 63, "A"), finding(64, 99, "B")], PathBuf::new(), 0);
        app.hex_scroll = 2;
        app.move_selection(1);
        assert_eq!(app.hex_scroll, 0);
    }

    #[test]
    fn scroll_hex_clamps_to_available_rows() {
        let data = vec![0u8; 100];
        // 64 байти -> 4 рядки по 16 байт (індекси рядків 0..=3)
        let mut app = App::new(&data, vec![finding(0, 63, "A")], PathBuf::new(), 0);

        app.scroll_hex(-1); // вже на 0
        assert_eq!(app.hex_scroll, 0);

        app.scroll_hex(2);
        assert_eq!(app.hex_scroll, 2);

        app.scroll_hex(100); // має зупинитись на останньому рядку (3), не вилетіти за межі
        assert_eq!(app.hex_scroll, 3);
    }

    #[test]
    fn toggle_focus_switches_between_list_and_hex() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![finding(0, 9, "A")], PathBuf::new(), 0);
        assert!(app.focus == Focus::List);
        app.toggle_focus();
        assert!(app.focus == Focus::Hex);
        app.toggle_focus();
        assert!(app.focus == Focus::List);
    }

    #[test]
    fn toggle_entropy_computes_then_clears_blocks() {
        let data = vec![0u8; 4096];
        let mut app = App::new(&data, vec![finding(0, 100, "A")], PathBuf::new(), 0);
        assert!(app.entropy_blocks.is_none());

        app.toggle_entropy();
        assert!(app.entropy_blocks.is_some());

        app.toggle_entropy();
        assert!(app.entropy_blocks.is_none());
    }

    #[test]
    fn clear_transient_status_restores_default_hint_text() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);

        app.status = "Витягнуто: /tmp/some_file.bin".to_string();
        app.clear_transient_status();

        assert_eq!(app.status, default_status());
    }

    #[test]
    fn normalize_key_code_maps_ukrainian_letters_to_same_physical_key() {
        // Пари (українська літера, англійська на тій самій фізичній клавіші)
        // для клавіш, що реально використовуються як гарячі в цьому файлі.
        let pairs = [
            ('й', 'q'),
            ('у', 'e'),
            ('к', 'r'),
            ('е', 't'),
            ('а', 'f'),
            ('р', 'h'),
            ('о', 'j'),
            ('л', 'k'),
            ('ч', 'x'),
            ('с', 'c'),
        ];
        for (ukrainian, english) in pairs {
            assert_eq!(
                normalize_key_code(KeyCode::Char(ukrainian)),
                KeyCode::Char(english),
                "'{ukrainian}' має нормалізуватись у '{english}'"
            );
        }
    }

    #[test]
    fn normalize_key_code_leaves_digits_and_non_char_keys_untouched() {
        assert_eq!(normalize_key_code(KeyCode::Char('5')), KeyCode::Char('5'));
        assert_eq!(normalize_key_code(KeyCode::Esc), KeyCode::Esc);
        assert_eq!(normalize_key_code(KeyCode::Enter), KeyCode::Enter);
    }

    #[test]
    fn is_high_entropy_detects_overlap_with_high_entropy_block() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![finding(0, 9, "A")], PathBuf::new(), 0);

        // Без обчисленої ентропії — завжди false.
        assert!(!app.is_high_entropy(&finding(0, 9, "A")));

        app.entropy_blocks = Some(vec![EntropyBlock {
            offset: 5,
            size: 10,
            entropy: 7.9,
            high: true,
        }]);

        assert!(app.is_high_entropy(&finding(0, 9, "A"))); // [0,9] перетинається з [5,15)
        assert!(!app.is_high_entropy(&finding(0, 3, "A"))); // [0,3] не перетинається з [5,15)
    }

    #[test]
    fn extract_single_writes_exact_byte_range() {
        let dir = std::env::temp_dir().join(format!("great_extractor_tui_test_{}", std::process::id()));
        let data: Vec<u8> = (0..50).collect();
        let f = finding(10, 19, "PNG");

        let out_path = extract_single(&data, &f, &dir).expect("extraction must succeed");
        let written = std::fs::read(&out_path).expect("output file must exist");
        assert_eq!(written, data[10..=19]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn available_formats_is_sorted_and_deduplicated() {
        let data = vec![0u8; 10];
        let findings = vec![finding(0, 1, "PNG"), finding(2, 3, "JPEG"), finding(4, 5, "PNG")];
        let app = App::new(&data, findings, PathBuf::new(), 0);
        assert_eq!(app.available_formats, vec!["JPEG".to_string(), "PNG".to_string()]);
    }

    #[test]
    fn format_filter_shows_only_matching_findings() {
        let data = vec![0u8; 10];
        let findings = vec![finding(0, 1, "PNG"), finding(2, 3, "JPEG"), finding(4, 5, "PNG")];
        let mut app = App::new(&data, findings, PathBuf::new(), 0);

        app.format_filter = Some("PNG".to_string());
        app.recompute_filtered();

        assert_eq!(app.filtered.len(), 2);
        assert!(app.filtered.iter().all(|&i| app.findings[i].format == "PNG"));
    }

    #[test]
    fn confidence_filter_hides_findings_below_threshold() {
        let data = vec![0u8; 10];
        let findings = vec![
            finding_with_confidence(0, 1, "A", 55),
            finding_with_confidence(2, 3, "B", 80),
            finding_with_confidence(4, 5, "C", 95),
        ];
        let mut app = App::new(&data, findings, PathBuf::new(), 0);

        app.apply_confidence_filter(80);

        assert_eq!(app.filtered.len(), 2);
        assert!(app.filtered.iter().all(|&i| app.findings[i].confidence >= 80));
    }

    #[test]
    fn reset_filters_restores_initial_min_confidence_and_clears_format() {
        let data = vec![0u8; 10];
        let findings = vec![finding_with_confidence(0, 1, "A", 41), finding_with_confidence(2, 3, "B", 95)];
        let mut app = App::new(&data, findings, PathBuf::new(), 41);

        app.format_filter = Some("B".to_string());
        app.apply_confidence_filter(95);
        assert_eq!(app.filtered.len(), 1);

        app.reset_filters();

        assert_eq!(app.format_filter, None);
        assert_eq!(app.confidence_filter, 41);
        assert_eq!(app.filtered.len(), 2);
    }

    #[test]
    fn format_menu_enter_applies_selected_format_and_closes_menu() {
        let data = vec![0u8; 10];
        let findings = vec![finding(0, 1, "JPEG"), finding(2, 3, "PNG")];
        let mut app = App::new(&data, findings, PathBuf::new(), 0);

        app.open_format_menu();
        // курсор 0 = "Усі формати", 1 = перший доступний формат за алфавітом (JPEG)
        app.handle_menu_key(KeyCode::Down);
        app.handle_menu_key(KeyCode::Enter);

        assert!(app.menu.is_none());
        assert_eq!(app.format_filter, Some("JPEG".to_string()));
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.findings[app.filtered[0]].format, "JPEG");
    }

    #[test]
    fn new_defaults_to_standard_theme() {
        let data = vec![0u8; 10];
        let app = App::new(&data, vec![], PathBuf::new(), 0);
        assert!(app.theme == ThemeKind::Standard);
    }

    #[test]
    fn theme_menu_enter_switches_active_theme() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);

        app.open_theme_menu();
        app.handle_menu_key(KeyCode::Down); // Standard -> MidnightCommander
        app.handle_menu_key(KeyCode::Enter);

        assert!(app.menu.is_none());
        assert!(app.theme == ThemeKind::MidnightCommander);
    }

    #[test]
    fn theme_menu_esc_cancels_without_changing_theme() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);

        app.open_theme_menu();
        app.handle_menu_key(KeyCode::Down);
        app.handle_menu_key(KeyCode::Esc);

        assert!(app.menu.is_none());
        assert!(app.theme == ThemeKind::Standard);
    }

    #[test]
    fn theme_menu_enter_persists_choice_when_config_path_is_set() {
        let path = std::env::temp_dir()
            .join(format!("great_extractor_tui_config_test_{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        app.config_path = Some(path.clone());

        app.open_theme_menu();
        app.handle_menu_key(KeyCode::Down); // Standard -> MidnightCommander
        app.handle_menu_key(KeyCode::Enter);

        let saved = config::load_from(&path);
        assert_eq!(saved.theme, "midnight_commander");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn theme_menu_enter_does_not_touch_disk_without_config_path() {
        // `App::new` лишає `config_path` порожнім саме для того, щоб юніт-тести
        // ніколи не чіпали файлову систему — цей тест лише документує це явно.
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        assert!(app.config_path.is_none());

        app.open_theme_menu();
        app.handle_menu_key(KeyCode::Down);
        app.handle_menu_key(KeyCode::Enter);

        assert!(app.config_path.is_none());
    }

    #[test]
    fn confidence_menu_custom_input_applies_typed_value() {
        let data = vec![0u8; 10];
        let findings = vec![finding_with_confidence(0, 1, "A", 55), finding_with_confidence(2, 3, "B", 95)];
        let mut app = App::new(&data, findings, PathBuf::new(), 0);

        app.open_confidence_menu(); // курсор 0 = "55%"
        app.handle_menu_key(KeyCode::Down); // 1 = "80%"
        app.handle_menu_key(KeyCode::Down); // 2 = "95%"
        app.handle_menu_key(KeyCode::Down); // 3 = "Власне значення..."
        app.handle_menu_key(KeyCode::Enter);
        app.handle_menu_key(KeyCode::Char('9'));
        app.handle_menu_key(KeyCode::Char('0'));
        app.handle_menu_key(KeyCode::Enter);

        assert!(app.menu.is_none());
        assert_eq!(app.confidence_filter, 90);
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.findings[app.filtered[0]].format, "B");
    }

    #[test]
    fn confidence_menu_esc_cancels_without_changing_filter() {
        let data = vec![0u8; 10];
        let findings = vec![finding(0, 1, "A")];
        let mut app = App::new(&data, findings, PathBuf::new(), 0);

        app.open_confidence_menu();
        app.handle_menu_key(KeyCode::Esc);

        assert!(app.menu.is_none());
        assert_eq!(app.confidence_filter, 0);
    }

    #[test]
    fn open_formats_help_shows_menu_with_zero_scroll() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        app.open_formats_help();
        assert!(matches!(app.menu, Some(Menu::FormatsHelp { scroll: 0 })));
    }

    #[test]
    fn formats_help_scroll_saturates_and_esc_closes() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        app.open_formats_help();

        app.handle_menu_key(KeyCode::Up); // вже на 0 — не має піти в мінус (saturating)
        assert!(matches!(app.menu, Some(Menu::FormatsHelp { scroll: 0 })));

        app.handle_menu_key(KeyCode::Down);
        assert!(matches!(app.menu, Some(Menu::FormatsHelp { scroll: 1 })));

        app.handle_menu_key(KeyCode::PageDown);
        assert!(matches!(app.menu, Some(Menu::FormatsHelp { scroll: 11 })));

        app.handle_menu_key(KeyCode::Esc);
        assert!(app.menu.is_none());
    }

    #[test]
    fn open_app_help_shows_menu_with_zero_scroll() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        app.open_app_help();
        assert!(matches!(app.menu, Some(Menu::AppHelp { scroll: 0 })));
    }

    #[test]
    fn app_help_scroll_saturates_and_esc_closes() {
        let data = vec![0u8; 10];
        let mut app = App::new(&data, vec![], PathBuf::new(), 0);
        app.open_app_help();

        app.handle_menu_key(KeyCode::Up); // вже на 0 — не має піти в мінус (saturating)
        assert!(matches!(app.menu, Some(Menu::AppHelp { scroll: 0 })));

        app.handle_menu_key(KeyCode::Down);
        assert!(matches!(app.menu, Some(Menu::AppHelp { scroll: 1 })));

        app.handle_menu_key(KeyCode::PageDown);
        assert!(matches!(app.menu, Some(Menu::AppHelp { scroll: 11 })));

        app.handle_menu_key(KeyCode::Esc);
        assert!(app.menu.is_none());
    }

    #[test]
    fn decode_as_text_reads_plain_utf8() {
        assert_eq!(decode_as_text(b"<svg>hello</svg>"), "<svg>hello</svg>");
    }

    #[test]
    fn decode_as_text_strips_utf8_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"text after bom");
        assert_eq!(decode_as_text(&bytes), "text after bom");
    }

    #[test]
    fn decode_as_text_decodes_utf16le_bom() {
        // "Windows Registry Editor Version 5.00", як реально зберігає regedit.
        let text = "Windows Registry Editor Version 5.00";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_as_text(&bytes), text);
    }

    #[test]
    fn decode_as_text_replaces_invalid_utf8_bytes() {
        let bytes = [b'a', 0xFF, b'b'];
        assert_eq!(decode_as_text(&bytes), "a\u{FFFD}b");
    }

    #[test]
    fn is_text_format_covers_known_text_formats_and_excludes_binary() {
        for format in ["SVG", "XPM", "EPS", "XFig", "PEM", "MBOX", "WebVTT", "ASS", "BDF", "FDF"] {
            assert!(is_text_format(format), "{format} має бути текстовим форматом");
        }
        for format in ["PNG", "ZIP", "ELF", "TTF"] {
            assert!(!is_text_format(format), "{format} не має бути текстовим форматом");
        }
    }

    #[test]
    fn scroll_hex_uses_text_line_count_for_text_formats() {
        let data = b"line1\nline2\nline3\nline4\n".to_vec();
        let mut app = App::new(&data, vec![finding(0, data.len() - 1, "SVG")], PathBuf::new(), 0);

        app.scroll_hex(100); // має зупинитись на останньому рядку, не вилетіти за межі
        assert_eq!(app.hex_scroll, 3);

        app.scroll_hex(-100);
        assert_eq!(app.hex_scroll, 0);
    }
}
