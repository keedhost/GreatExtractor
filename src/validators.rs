//! Структурні валідатори — на відміну від простого пошуку байтового маркера
//! кінця, ці функції розбирають внутрішню структуру формату (заголовки,
//! таблиці розмірів тощо), щоб отримати точну межу вбудованого файлу.
//!
//! Кожен валідатор має сигнатуру `fn(&[u8], usize) -> Option<(usize, u8)>`:
//! приймає повні дані та абсолютний офсет початку файлу, повертає
//! `(offset_end, confidence)` або `None`, якщо структуру розібрати не вдалося
//! (тоді сканер відкотиться до евристики).

/// Захист від zip-бомб для GZIP (`deflate_stream_len`) і zlib/SWF
/// (`zlib_stream_len`): якщо розпакований обсяг потоку перевищує цю межу,
/// валідація переривається і повертається `None` (відкат до евристичної
/// межі). Пам'ять при цьому не росте (один перевикористовуваний 64 KiB
/// буфер), але сам CPU-час розпакування зростає лінійно з лімітом — а
/// сканер запускає цю перевірку на КОЖНОМУ кандидаті сигнатури (`\x1f\x8b\x08`
/// трапляється як 3-байтовий збіг доволі часто на щільних бінарних файлах),
/// тож надто високий ліміт — це CPU-DoS через ампліфікацію: один крафтований
/// файл із багатьма такими кандидатами змусив би витратити ліміт-часу на
/// кожен із них. 512 MiB — з великим запасом покриває реальні вбудовані
/// стиснені дані (це межа виявлення, а не розпакування для використання).
const MAX_GZIP_DECOMPRESS_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// ZIP: проходить структуру локальних заголовків і заголовків центрального
/// каталогу, використовуючи заявлені розміри записів (а не пошук байтів),
/// щоб коректно "перестрибувати" крізь вкладені файли (в т.ч. вкладені ZIP)
/// і дістатися справжнього End Of Central Directory (EOCD) цього архіву.
pub fn validate_zip(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const LOCAL_SIG: &[u8] = b"PK\x03\x04";
    const CENTRAL_SIG: &[u8] = b"PK\x01\x02";
    const EOCD_SIG: &[u8] = b"PK\x05\x06";
    const DATA_DESCRIPTOR_FLAG: u16 = 1 << 3;

    let mut pos = start;

    // Локальні файлові заголовки
    while data.get(pos..pos + 4)? == LOCAL_SIG {
        let flags = u16::from_le_bytes(data.get(pos + 6..pos + 8)?.try_into().ok()?);
        let compressed_size = u32::from_le_bytes(data.get(pos + 18..pos + 22)?.try_into().ok()?) as usize;
        let name_len = u16::from_le_bytes(data.get(pos + 26..pos + 28)?.try_into().ok()?) as usize;
        let extra_len = u16::from_le_bytes(data.get(pos + 28..pos + 30)?.try_into().ok()?) as usize;
        let header_end = pos + 30 + name_len + extra_len;

        if flags & DATA_DESCRIPTOR_FLAG != 0 {
            // Розмір невідомий заздалегідь (потокове стиснення) — розмір
            // з'ясовується лише опційним дескриптором після даних. Без
            // повторного розпакування точно перестрибнути неможливо, тож
            // шукаємо найближчий наступний PK-заголовок як орієнтир.
            pos = find_next_pk_marker(data, header_end)?;
        } else {
            pos = header_end + compressed_size;
        }
        if pos > data.len() {
            return None;
        }
    }

    // Заголовки центрального каталогу
    while data.get(pos..pos + 4)? == CENTRAL_SIG {
        let name_len = u16::from_le_bytes(data.get(pos + 28..pos + 30)?.try_into().ok()?) as usize;
        let extra_len = u16::from_le_bytes(data.get(pos + 30..pos + 32)?.try_into().ok()?) as usize;
        let comment_len = u16::from_le_bytes(data.get(pos + 32..pos + 34)?.try_into().ok()?) as usize;
        pos += 46 + name_len + extra_len + comment_len;
        if pos > data.len() {
            return None;
        }
    }

    // End Of Central Directory
    if data.get(pos..pos + 4)? != EOCD_SIG {
        return None;
    }
    let comment_len = u16::from_le_bytes(data.get(pos + 20..pos + 22)?.try_into().ok()?) as usize;
    let end = (pos + 22 + comment_len).saturating_sub(1);
    if end >= data.len() {
        return None;
    }
    Some((end, 95))
}

fn find_next_pk_marker(data: &[u8], from: usize) -> Option<usize> {
    memchr::memmem::find(data.get(from..)?, b"PK").map(|rel| from + rel)
}

/// GZIP: розбирає заголовок (з опційними полями FEXTRA/FNAME/FCOMMENT/FHCRC),
/// тоді пропускає стиснений DEFLATE-потік, фактично розпаковуючи його лише
/// для того, щоб дізнатися, скільки байтів він займає (RFC 1952 не містить
/// довжини стиснених даних явно) — і нарешті перевіряє 8-байтовий трейлер
/// (CRC32 + ISIZE).
pub fn validate_gzip(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let flg = *data.get(start + 3)?;
    let mut pos = start + 10;

    const FEXTRA: u8 = 0x04;
    const FNAME: u8 = 0x08;
    const FCOMMENT: u8 = 0x10;
    const FHCRC: u8 = 0x02;

    if flg & FEXTRA != 0 {
        let xlen = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
        pos += 2 + xlen;
    }
    if flg & FNAME != 0 {
        pos = skip_cstring(data, pos)?;
    }
    if flg & FCOMMENT != 0 {
        pos = skip_cstring(data, pos)?;
    }
    if flg & FHCRC != 0 {
        pos += 2;
    }
    if pos > data.len() {
        return None;
    }

    let compressed_len = deflate_stream_len(data.get(pos..)?)?;
    let trailer_start = pos + compressed_len;
    if trailer_start + 8 > data.len() {
        return None;
    }
    Some((trailer_start + 8 - 1, 95))
}

fn skip_cstring(data: &[u8], from: usize) -> Option<usize> {
    let nul = memchr::memchr(0, data.get(from..)?)?;
    Some(from + nul + 1)
}

/// Пропускає raw DEFLATE потік, повертаючи кількість спожитих вхідних байтів.
fn deflate_stream_len(input: &[u8]) -> Option<usize> {
    let mut decompress = flate2::Decompress::new(false);
    let mut out = vec![0u8; 64 * 1024];

    loop {
        let before_in = decompress.total_in();
        let before_out = decompress.total_out();
        let consumed_so_far = before_in as usize;
        let status = decompress
            .decompress(&input[consumed_so_far..], &mut out, flate2::FlushDecompress::None)
            .ok()?;

        match status {
            flate2::Status::StreamEnd => return Some(decompress.total_in() as usize),
            flate2::Status::Ok => {
                let made_progress = decompress.total_in() > before_in || decompress.total_out() > before_out;
                if !made_progress || decompress.total_out() > MAX_GZIP_DECOMPRESS_BYTES {
                    return None;
                }
            }
            flate2::Status::BufError => return None,
        }
    }
}

/// TAR: проходить послідовність 512-байтових блоків заголовків, читаючи
/// заявлений розмір кожного файлу (поле у форматі USTAR), доки не
/// зустріне пару нульових блоків — стандартний маркер кінця архіву.
pub fn validate_tar(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const BLOCK: usize = 512;

    let mut pos = start;
    let mut last_entry_end = None;

    while let Some(header) = data.get(pos..pos + BLOCK) {
        if header.iter().all(|&b| b == 0) {
            let mut end = pos + BLOCK - 1;
            if let Some(next) = data.get(pos + BLOCK..pos + 2 * BLOCK)
                && next.iter().all(|&b| b == 0)
            {
                end = pos + 2 * BLOCK - 1;
            }
            return Some((end, 95));
        }

        if &header[257..262] != b"ustar" {
            break;
        }

        // GNU base-256 розширення розміру (старший біт першого байта) не підтримується.
        let size = match parse_octal(&header[124..136]) {
            Some(size) if header[124] & 0x80 == 0 => size,
            _ => break,
        };
        let data_blocks = (size as usize).div_ceil(BLOCK);
        last_entry_end = Some(pos + BLOCK + data_blocks * BLOCK - 1);
        pos += BLOCK + data_blocks * BLOCK;
    }

    // Дійшли до пошкодженого/обрізаного запису — повертаємо межу останнього
    // повністю розібраного файлу з нижчою впевненістю, оскільки явного
    // кінця архіву (нульових блоків) не знайдено.
    last_entry_end.map(|end| (end, 70))
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .copied()
        .collect::<Vec<u8>>();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(std::str::from_utf8(&text).ok()?, 8).ok()
}

/// ELF: межу файлу неможливо взяти з єдиного поля, тому беремо максимум із
/// (а) кінця таблиці заголовків секцій та (б) кінця найдальшого сегмента
/// програми (`p_offset + p_filesz`) — цього достатньо для переважної
/// більшості реальних ELF-файлів.
pub fn validate_elf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let bytes = data.get(start..)?;
    let elf = goblin::elf::Elf::parse(bytes).ok()?;

    let mut end: u64 = 0;

    if elf.header.e_shnum > 0 {
        end = end.max(elf.header.e_shoff + elf.header.e_shentsize as u64 * elf.header.e_shnum as u64);
    }
    for phdr in &elf.program_headers {
        end = end.max(phdr.p_offset + phdr.p_filesz);
    }

    if end == 0 || start as u64 + end > data.len() as u64 {
        return None;
    }
    Some(((start as u64 + end - 1) as usize, 80))
}

/// PE: межу файлу оцінюємо як кінець найдальшої секції (`PointerToRawData +
/// SizeOfRawData`). Не враховує таблицю сертифікатів підпису (Authenticode),
/// що йде за секціями — для підписаних файлів реальний кінець може бути далі.
pub fn validate_pe(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let bytes = data.get(start..)?;
    let pe = goblin::pe::PE::parse(bytes).ok()?;

    let end = pe
        .sections
        .iter()
        .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
        .max()?;

    if end == 0 || start as u64 + end > data.len() as u64 {
        return None;
    }
    Some(((start as u64 + end - 1) as usize, 75))
}

/// Спільна логіка для всієй родини PNG-подібних форматів (PNG/MNG/JNG) —
/// проходить послідовність чанків (`length`(4) + `type`(4) + `data` +
/// `crc`(4)), не звіряючи CRC, доки не зустріне чанк-термінатор.
fn validate_png_family(data: &[u8], start: usize, signature: &[u8], end_chunk: &[u8]) -> Option<(usize, u8)> {
    if data.get(start..start + signature.len())? != signature {
        return None;
    }

    let mut pos = start + signature.len();
    loop {
        let length = u32::from_be_bytes(data.get(pos..pos + 4)?.try_into().ok()?) as usize;
        let chunk_type = data.get(pos + 4..pos + 8)?;
        let chunk_end = pos + 8 + length + 4; // length + type(4) + data(length) + crc(4)

        if chunk_end > data.len() {
            return None;
        }
        if chunk_type == end_chunk {
            return Some((chunk_end - 1, 95));
        }
        pos = chunk_end;
    }
}

/// PNG: доки не зустріне чанк `IEND` — стандартний маркер кінця зображення.
pub fn validate_png(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_png_family(data, start, b"\x89PNG\r\n\x1a\n", b"IEND")
}

/// MNG (Multiple-image Network Graphics, анімований "родич" PNG): та ж
/// структура чанків, термінатор — `MEND`.
pub fn validate_mng(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_png_family(data, start, b"\x8aMNG\r\n\x1a\n", b"MEND")
}

/// JNG (JPEG-in-PNG-container "родич" PNG): та ж структура чанків,
/// термінатор — `JEND`.
pub fn validate_jng(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_png_family(data, start, b"\x8bJNG\r\n\x1a\n", b"JEND")
}

/// JPEG: проходить послідовність маркерів (`FFxx` + за потреби 2-байтова
/// довжина сегмента), доки не зустріне `FFD9` (EOI). Сегмент `SOS` (`FFDA`)
/// не має явної довжини ентропійно закодованих даних, що йдуть за його
/// заголовком, тож ці дані пропускаються байт-за-байтом до першого "справжнього"
/// маркера — байти `FF 00` є byte-stuffing (літеральний `0xFF` у потоці даних),
/// а маркери відновлення `FFD0`-`FFD7` не завершують скан, тож також пропускаються.
pub fn validate_jpeg(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 2)? != b"\xff\xd8" {
        return None;
    }

    let mut pos = start + 2;
    loop {
        if *data.get(pos)? != 0xFF {
            return None;
        }
        let mut marker_pos = pos + 1;
        let mut marker = *data.get(marker_pos)?;
        while marker == 0xFF {
            marker_pos += 1;
            marker = *data.get(marker_pos)?;
        }
        pos = marker_pos + 1;

        match marker {
            0xD9 => return Some((pos - 1, 95)),
            0x01 | 0xD0..=0xD7 => {} // TEM/RSTn: без поля довжини
            0xDA => {
                let length = u16::from_be_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
                if length < 2 {
                    return None;
                }
                pos = skip_scan_data(data, pos + length)?;
            }
            _ => {
                let length = u16::from_be_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
                if length < 2 {
                    return None;
                }
                pos += length;
            }
        }
        if pos > data.len() {
            return None;
        }
    }
}

/// SQLite: розмір бази даних дорівнює `page_size * page_count`, обидва поля
/// зберігаються у 100-байтовому заголовку. `page_count` (за офсетом 28) може
/// бути нульовим у застарілих файлах ("in-header database size is not valid") —
/// тоді точний розмір неможливо визначити без повного проходу по файлу, і
/// валідатор відмовляється від точної межі. Якщо "лічильник змін" (offset 24)
/// збігається з "version-valid-for" (offset 92), заголовок гарантовано
/// синхронізований з фактичним станом файлу — тоді впевненість вища.
pub fn validate_sqlite(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let header = data.get(start..start + 100)?;

    let page_size_raw = u16::from_be_bytes(header[16..18].try_into().ok()?);
    let page_size: u64 = match page_size_raw {
        1 => 65536, // особливе значення: сторінка 64 KiB (не вміщується у u16)
        n if n.is_power_of_two() && (512..=32768).contains(&n) => n as u64,
        _ => return None,
    };

    let change_counter = u32::from_be_bytes(header[24..28].try_into().ok()?);
    let page_count = u32::from_be_bytes(header[28..32].try_into().ok()?);
    let version_valid_for = u32::from_be_bytes(header[92..96].try_into().ok()?);

    if page_count == 0 {
        return None;
    }

    let total_size = page_size.checked_mul(page_count as u64)?;
    let end = (start as u64).checked_add(total_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }

    let confidence = if change_counter == version_valid_for { 90 } else { 60 };
    Some((end as usize, confidence))
}

/// RAR (стрий формат 1.5-4.x): проходить послідовність блоків спільного
/// заголовку (`HEAD_CRC`(2) + `HEAD_TYPE`(1) + `HEAD_FLAGS`(2) + `HEAD_SIZE`(2)),
/// де `HEAD_SIZE` — повний розмір заголовку блоку (включно з
/// type-специфічними полями), а за наявності прапорця `LONG_BLOCK` (0x8000)
/// одразу після заголовку йде ще 4-байтове поле `ADD_SIZE` — розмір даних,
/// що йдуть за заголовком (напр. стиснутий вміст файлу для `FILE_HEAD`).
/// Завершується на блоці `ENDARC_HEAD` (0x7b); якщо його не знайдено (архів
/// без явного кінця), повертає межу останнього повністю розібраного блоку з
/// нижчою впевненістю — так само, як TAR-валідатор.
pub fn validate_rar(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const MARKER_LEN: usize = 7; // "Rar!\x1a\x07\x00"
    const ENDARC_HEAD: u8 = 0x7b;
    const LONG_BLOCK: u16 = 0x8000;

    let mut pos = start + MARKER_LEN;
    let mut last_good_end = pos - 1;

    while let Some(header) = data.get(pos..pos + 7) {
        let head_type = header[2];
        let head_flags = u16::from_le_bytes(header[3..5].try_into().ok()?);
        let head_size = u16::from_le_bytes(header[5..7].try_into().ok()?) as usize;

        if head_size < 7 {
            break;
        }

        let add_size = if head_flags & LONG_BLOCK != 0 {
            match data.get(pos + 7..pos + 11) {
                Some(b) => u32::from_le_bytes(b.try_into().ok()?) as usize,
                None => break,
            }
        } else {
            0
        };

        let block_end = pos + head_size + add_size;
        if block_end > data.len() {
            break;
        }

        last_good_end = block_end - 1;
        pos = block_end;

        if head_type == ENDARC_HEAD {
            return Some((last_good_end, 90));
        }
    }

    if last_good_end + 1 > start + MARKER_LEN {
        Some((last_good_end, 65))
    } else {
        None
    }
}

/// 7-Zip: фіксований 32-байтовий заголовок сигнатури складається з `magic`(6),
/// `version`(2), `StartHeaderCRC`(4) та власне `StartHeader` —
/// `NextHeaderOffset`(8), `NextHeaderSize`(8), `NextHeaderCRC`(4). Разом ці
/// два поля вказують, де в архіві лежить заключний блок метаданих ("next
/// header"); його кінець і є кінцем усього файлу. CRC полів не перевіряється
/// (як і для PNG), тож упевненість трохи нижча за формати з повною
/// структурною верифікацією (ZIP/GZIP/TAR).
pub fn validate_7z(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const SIGNATURE_HEADER_LEN: u64 = 32;

    let header = data.get(start..start + SIGNATURE_HEADER_LEN as usize)?;
    let next_header_offset = u64::from_le_bytes(header[12..20].try_into().ok()?);
    let next_header_size = u64::from_le_bytes(header[20..28].try_into().ok()?);

    let total = SIGNATURE_HEADER_LEN
        .checked_add(next_header_offset)?
        .checked_add(next_header_size)?;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }

    Some((end as usize, 85))
}

/// Пропускає ентропійно закодовані дані скану JPEG, повертаючи офсет першого
/// байта `0xFF`, що починає справжній наступний маркер (не byte-stuffing і не
/// маркер відновлення).
fn skip_scan_data(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let idx = pos + memchr::memchr(0xFF, data.get(pos..)?)?;
        let next = *data.get(idx + 1)?;
        if next == 0x00 || (0xD0..=0xD7).contains(&next) {
            pos = idx + 2;
            continue;
        }
        return Some(idx);
    }
}

/// RIFF-контейнер (WebP, сучасний CorelDRAW CDR тощо): поле `ChunkSize`
/// (offset 4, 4 байти LE) прямо вказує розмір усього, що йде після нього —
/// `total_size = 8 + ChunkSize`. Не залежить від конкретного form-типу
/// (`WEBP`, `CDR6` тощо), тож придатний як спільний валідатор для будь-якого
/// RIFF-формату.
pub fn validate_riff(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"RIFF" {
        return None;
    }
    let chunk_size = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(8)?.checked_add(chunk_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// ICO/CUR (Windows icon/cursor): за директорією записів (по 16 байт кожен)
/// беремо максимум `image_offset + bytes_in_res` — це і є кінець
/// найдальшого вбудованого зображення, тобто кінець усього файлу.
/// Розміри `biSize` (перше поле `BITMAPINFOHEADER`-родини), що реально
/// трапляються у зображеннях, вбудованих в ICO/CUR (BITMAPCOREHEADER..BITMAPV5HEADER).
const ICO_VALID_DIB_SIZES: [u32; 6] = [12, 40, 52, 56, 64, 108];

/// Чи виглядають байти за вказаним офсетом як початок реального зображення,
/// вбудованого в ICO/CUR (PNG або DIB-заголовок). Без цієї перевірки
/// валідатор лише узгоджував арифметику самого directory-запису — на
/// щільних бінарних файлах (дампи дисків, файлові системи) це "підтверджує"
/// майже будь-який 4-байтовий збіг на слабку сигнатуру.
fn looks_like_ico_image_data(data: &[u8], offset: usize) -> bool {
    if data.get(offset..offset + 8) == Some(&b"\x89PNG\r\n\x1a\n"[..]) {
        return true;
    }
    let Some(bi_size_bytes) = data.get(offset..offset + 4) else {
        return false;
    };
    let bi_size = u32::from_le_bytes(bi_size_bytes.try_into().unwrap());
    ICO_VALID_DIB_SIZES.contains(&bi_size)
}

pub fn validate_ico(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let header = data.get(start..start + 6)?;
    if header[0..2] != [0, 0] {
        return None;
    }
    let img_type = u16::from_le_bytes(header[2..4].try_into().ok()?);
    if img_type != 1 && img_type != 2 {
        return None; // 1 = ICO, 2 = CUR
    }
    let count = u16::from_le_bytes(header[4..6].try_into().ok()?) as usize;
    if count == 0 {
        return None;
    }

    let entries_start = start + 6;
    let directory_len = (6 + count * 16) as u64;
    let entries = data.get(entries_start..entries_start + count * 16)?;

    let mut max_end: u64 = 0;
    for entry in entries.chunks_exact(16) {
        let bytes_in_res = u32::from_le_bytes(entry[8..12].try_into().ok()?) as u64;
        let image_offset = u32::from_le_bytes(entry[12..16].try_into().ok()?) as u64;

        // Зображення не може починатися всередині заголовка/каталогу, і за
        // цим офсетом мають бути реальні байти PNG- чи DIB-зображення.
        if image_offset < directory_len || bytes_in_res == 0 {
            return None;
        }
        let image_start = (start as u64).checked_add(image_offset)?;
        if !looks_like_ico_image_data(data, usize::try_from(image_start).ok()?) {
            return None;
        }

        max_end = max_end.max(image_offset + bytes_in_res);
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// ICNS (Apple Icon Image): загальний розмір файлу зберігається прямо у
/// заголовку (offset 4, 4 байти BE) — найпростіший з усіх валідаторів.
pub fn validate_icns(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"icns" {
        return None;
    }
    let file_len = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(file_len)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 95))
}

/// ISOBMFF (контейнер боксів `size`(4,BE)+`type`(4)[+`extended_size`(8) якщо
/// `size == 1`], що лежить в основі HEIC/AVIF/JP2/JXL): проходить top-level
/// бокси, доки не дійде точно до кінця даних (успіх — це і межа файлу) або не
/// зустріне бокс, що виходить за наявні дані (обрізаний файл чи "сміття"
/// після архіву — повертає межу останнього повністю розібраного боксу з
/// нижчою впевненістю, як TAR/RAR-фолбек). `size == 0` — формально коректне
/// значення, що означає "бокс триває до кінця файлу".
pub fn validate_isobmff(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let mut pos = start;
    let mut last_good_end: Option<usize> = None;

    while let Some(header) = data.get(pos..pos + 8) {
        let box_size = u32::from_be_bytes(header[0..4].try_into().ok()?) as u64;

        if box_size == 0 {
            return Some((data.len() - 1, 85));
        }

        let total_len = if box_size == 1 {
            u64::from_be_bytes(data.get(pos + 8..pos + 16)?.try_into().ok()?)
        } else {
            box_size
        };
        if total_len < 8 {
            break;
        }

        let box_end = pos as u64 + total_len;
        if box_end > data.len() as u64 {
            break;
        }

        last_good_end = Some(box_end as usize - 1);
        pos = box_end as usize;

        if pos == data.len() {
            return Some((pos - 1, 90));
        }
    }

    last_good_end.map(|end| (end, 70))
}

/// EPS (DOS EPS Binary File Header): 30-байтовий заголовок містить три пари
/// (offset, length) для вбудованих PostScript/WMF-preview/TIFF-preview
/// секцій — межа файлу є максимумом `offset+length` серед них.
pub fn validate_eps_binary_header(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let header = data.get(start..start + 30)?;

    let mut max_end: u64 = 0;
    for i in 0..3 {
        let off = u32::from_le_bytes(header[4 + i * 8..8 + i * 8].try_into().ok()?) as u64;
        let len = u32::from_le_bytes(header[8 + i * 8..12 + i * 8].try_into().ok()?) as u64;
        if len > 0 {
            max_end = max_end.max(off + len);
        }
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// WMF: опційний 22-байтовий "placeable"-заголовок (розпізнається за власним
/// магічним числом `D7CDC69A`, обраним саме для унеможливлення випадкових
/// збігів) передує стандартному заголовку метафайлу, чиє поле `fileSize`
/// (у 16-бітних словах) прямо дає точний розмір файлу. Без "placeable"-обгортки
/// стандартний заголовок розпізнається лише за `fileType`∈{1,2} і
/// `headerSize`=9 — цих двох малих цілих чисел значно менше для
/// однозначної ідентифікації, тож упевненість у цьому випадку нижча.
pub fn validate_wmf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const PLACEABLE: &[u8] = b"\xd7\xcd\xc6\x9a\x00\x00";

    let (header_start, is_placeable) = if data.get(start..start + PLACEABLE.len())? == PLACEABLE {
        (start + 22, true)
    } else {
        (start, false)
    };

    let file_type = u16::from_le_bytes(data.get(header_start..header_start + 2)?.try_into().ok()?);
    let header_size = u16::from_le_bytes(data.get(header_start + 2..header_start + 4)?.try_into().ok()?);
    if (file_type != 1 && file_type != 2) || header_size != 9 {
        return None;
    }

    let file_size_words = u32::from_le_bytes(data.get(header_start + 6..header_start + 10)?.try_into().ok()?) as u64;
    // fileSize включає сам METAHEADER (header_size слів) — менше значення
    // означає сміттєвий збіг на магічну послідовність, а не справжній WMF;
    // без цієї перевірки таке значення давало б end < start (underflow).
    if file_size_words < header_size as u64 {
        return None;
    }
    let core_bytes = file_size_words.checked_mul(2)?; // fileSize зберігається у 16-бітних словах

    let end = (header_start as u64).checked_add(core_bytes)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }

    let confidence = if is_placeable { 90 } else { 55 };
    Some((end as usize, confidence))
}

/// EMF: поле `nBytes` заголовка `ENHMETAHEADER` (офсет 48 від початку
/// заголовка) прямо містить точний розмір усього метафайлу в байтах.
pub fn validate_emf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start + 40..start + 44)? != b" EMF" {
        return None;
    }
    let n_bytes = u32::from_le_bytes(data.get(start + 48..start + 52)?.try_into().ok()?) as u64;

    let end = (start as u64).checked_add(n_bytes)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

fn read_u32_at(data: &[u8], pos: usize, is_be: bool) -> Option<u32> {
    let b = data.get(pos..pos + 4)?;
    Some(if is_be {
        u32::from_be_bytes(b.try_into().ok()?)
    } else {
        u32::from_le_bytes(b.try_into().ok()?)
    })
}

fn read_u64_at(data: &[u8], pos: usize, is_be: bool) -> Option<u64> {
    let b = data.get(pos..pos + 8)?;
    Some(if is_be {
        u64::from_be_bytes(b.try_into().ok()?)
    } else {
        u64::from_le_bytes(b.try_into().ok()?)
    })
}

/// Mach-O (macOS/NeXTSTEP, 32/64-біт, будь-який порядок байтів — конкретний
/// варіант визначається сигнатурою, що спрацювала): проходить усі load
/// commands (крок навігації — завжди авторитетне поле `cmdsize`, незалежно
/// від того, чи розпізнано конкретний тип команди) і для відомих типів бере
/// `fileoff+filesize` (`LC_SEGMENT`/`LC_SEGMENT_64`), positions
/// symbol/string-таблиць (`LC_SYMTAB`) та blob підпису коду
/// (`LC_CODE_SIGNATURE` — у сучасних підписаних бінарників це майже завжди
/// найдальший фрагмент файлу). Максимум серед усіх них і є кінцем файлу.
fn validate_macho_generic(data: &[u8], start: usize, is64: bool, is_be: bool) -> Option<(usize, u8)> {
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_CODE_SIGNATURE: u32 = 0x1d;

    let header_len: u64 = if is64 { 32 } else { 28 };
    let ncmds = read_u32_at(data, start + 16, is_be)? as usize;
    let sizeofcmds = read_u32_at(data, start + 20, is_be)? as u64;

    let mut max_end = start as u64 + header_len + sizeofcmds;
    let mut pos = start + header_len as usize;

    for _ in 0..ncmds {
        let cmd = read_u32_at(data, pos, is_be)?;
        let cmdsize = read_u32_at(data, pos + 4, is_be)? as usize;
        if cmdsize < 8 {
            return None;
        }

        match cmd {
            LC_SEGMENT if cmdsize >= 56 => {
                let fileoff = read_u32_at(data, pos + 32, is_be)? as u64;
                let filesize = read_u32_at(data, pos + 36, is_be)? as u64;
                max_end = max_end.max(start as u64 + fileoff + filesize);
            }
            LC_SEGMENT_64 if cmdsize >= 72 => {
                // vmaddr(8)+vmsize(8) ідуть перед fileoff/filesize у 64-бітній
                // версії структури (усі поля 8-байтові, на відміну від 32-бітної) —
                // тож зсуви 40/48, а не 32/40, як у LC_SEGMENT.
                let fileoff = read_u64_at(data, pos + 40, is_be)?;
                let filesize = read_u64_at(data, pos + 48, is_be)?;
                max_end = max_end.max(start as u64 + fileoff + filesize);
            }
            LC_SYMTAB if cmdsize >= 24 => {
                let symoff = read_u32_at(data, pos + 8, is_be)? as u64;
                let nsyms = read_u32_at(data, pos + 12, is_be)? as u64;
                let stroff = read_u32_at(data, pos + 16, is_be)? as u64;
                let strsize = read_u32_at(data, pos + 20, is_be)? as u64;
                let nlist_size: u64 = if is64 { 16 } else { 12 };
                max_end = max_end.max(start as u64 + symoff + nsyms * nlist_size);
                max_end = max_end.max(start as u64 + stroff + strsize);
            }
            LC_CODE_SIGNATURE if cmdsize >= 16 => {
                let dataoff = read_u32_at(data, pos + 8, is_be)? as u64;
                let datasize = read_u32_at(data, pos + 12, is_be)? as u64;
                max_end = max_end.max(start as u64 + dataoff + datasize);
            }
            _ => {}
        }

        pos += cmdsize;
    }

    if max_end == 0 || max_end > data.len() as u64 {
        return None;
    }
    Some(((max_end - 1) as usize, 80))
}

pub fn validate_macho_32be(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_macho_generic(data, start, false, true)
}

pub fn validate_macho_32le(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_macho_generic(data, start, false, false)
}

pub fn validate_macho_64be(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_macho_generic(data, start, true, true)
}

pub fn validate_macho_64le(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_macho_generic(data, start, true, false)
}

/// Mach-O Fat/Universal Binary: заголовок (завжди big-endian, незалежно від
/// вкладених архітектур) містить масив записів `(cputype, cpusubtype,
/// offset, size, align)` по 20 байт кожен — межа файлу є максимумом
/// `offset+size` серед них.
pub fn validate_macho_fat(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"\xca\xfe\xba\xbe" {
        return None;
    }
    let nfat_arch = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as usize;
    if nfat_arch == 0 || nfat_arch > 100 {
        return None; // типові universal binaries мають 1-5 архітектур
    }

    let arches_start = start + 8;
    let arches = data.get(arches_start..arches_start + nfat_arch * 20)?;

    let mut max_end: u64 = 0;
    for arch in arches.chunks_exact(20) {
        let offset = u32::from_be_bytes(arch[8..12].try_into().ok()?) as u64;
        let size = u32::from_be_bytes(arch[12..16].try_into().ok()?) as u64;
        max_end = max_end.max(offset + size);
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// PEF (Preferred Executable Format — класичні застосунки Mac OS PowerPC під
/// Code Fragment Manager, а також BeOS/PPC): 40-байтовий заголовок
/// контейнера має `sectionCount` (offset 32), за яким іде масив 28-байтових
/// заголовків секцій — межа файлу є максимумом `containerOffset+packedSize`
/// серед них.
pub fn validate_pef(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_LEN: usize = 40;
    const SECTION_LEN: usize = 28;

    if data.get(start..start + 8)? != b"Joy!peff" {
        return None;
    }
    let section_count = u16::from_be_bytes(data.get(start + 32..start + 34)?.try_into().ok()?) as usize;
    if section_count == 0 {
        return None;
    }

    let sections_start = start + HEADER_LEN;
    let sections = data.get(sections_start..sections_start + section_count * SECTION_LEN)?;

    let mut max_end: u64 = 0;
    for section in sections.chunks_exact(SECTION_LEN) {
        let packed_size = u32::from_be_bytes(section[16..20].try_into().ok()?) as u64;
        let container_offset = u32::from_be_bytes(section[20..24].try_into().ok()?) as u64;
        max_end = max_end.max(container_offset + packed_size);
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

/// IFF (родовий контейнер-попередник RIFF, той самий принцип, але
/// big-endian; використовується AIFF/AIFC та Amiga 8SVX): поле `ckSize`
/// (offset 4, 4 байти BE) прямо вказує розмір усього, що йде після нього.
pub fn validate_iff(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"FORM" {
        return None;
    }
    let chunk_size = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(8)?.checked_add(chunk_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// Ogg (контейнер Vorbis/Opus/Speex/Ogg-FLAC): проходить послідовність
/// сторінок (`OggS` + заголовок(27) + `segment_table`, розмір сторінки =
/// сума значень segment_table), доки не зустріне сторінку з прапорцем
/// `EOS`(0x04) — це і є кінець потоку. Без EOS (обрізаний файл) повертає
/// межу останньої повністю розібраної сторінки з нижчою впевненістю.
pub fn validate_ogg(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const EOS: u8 = 0x04;

    let mut pos = start;
    let mut last_good_end: Option<usize> = None;

    while let Some(header) = data.get(pos..pos + 27) {
        if header[0..4] != *b"OggS" {
            break;
        }
        let header_type = header[5];
        let page_segments = header[26] as usize;

        let Some(segment_table) = data.get(pos + 27..pos + 27 + page_segments) else {
            break;
        };
        let page_data_size: u64 = segment_table.iter().map(|&b| b as u64).sum();
        let page_total = 27u64 + page_segments as u64 + page_data_size;
        let page_end = pos as u64 + page_total;
        if page_end > data.len() as u64 {
            break;
        }

        last_good_end = Some(page_end as usize - 1);
        pos = page_end as usize;

        if header_type & EOS != 0 {
            return Some((last_good_end.unwrap(), 90));
        }
    }

    last_good_end.map(|end| (end, 70))
}

/// ASF (контейнер WMA/WMV): у Header Object проходить вкладені об'єкти в
/// пошуках File Properties Object — його поле `FileSize` прямо містить
/// точний розмір усього файлу (вимірюється від самого початку файлу).
pub fn validate_asf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_GUID: &[u8] = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
    const FILE_PROPERTIES_GUID: &[u8] = b"\xa1\xdc\xab\x8c\x47\xa9\xcf\x11\x8e\xe4\x00\xc0\x0c\x20\x53\x65";

    if data.get(start..start + 16)? != HEADER_GUID {
        return None;
    }
    let num_objects = u32::from_le_bytes(data.get(start + 24..start + 28)?.try_into().ok()?) as usize;

    let mut pos = start + 30;
    for _ in 0..num_objects {
        let guid = data.get(pos..pos + 16)?;
        let obj_size = u64::from_le_bytes(data.get(pos + 16..pos + 24)?.try_into().ok()?);
        if obj_size < 24 {
            return None;
        }

        if guid == FILE_PROPERTIES_GUID {
            let file_size = u64::from_le_bytes(data.get(pos + 40..pos + 48)?.try_into().ok()?);
            let end = (start as u64).checked_add(file_size)?.checked_sub(1)?;
            if end >= data.len() as u64 {
                return None;
            }
            return Some((end as usize, 90));
        }

        pos += obj_size as usize;
    }

    None
}

/// DSF (Sony DSD Stream File): заголовок прямо містить точний розмір усього
/// файлу в полі `fileSize` (offset 12, 8 байт LE) — найпростіший з усіх
/// аудіо-валідаторів.
pub fn validate_dsf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"DSD " {
        return None;
    }
    let file_size = u64::from_le_bytes(data.get(start + 12..start + 20)?.try_into().ok()?);
    let end = (start as u64).checked_add(file_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 95))
}

/// CAF (Apple Core Audio Format): проходить послідовність чанків
/// (`type`(4)+`size`(8,BE,знаковий) + дані), доки не дійде точно до кінця
/// даних (успіх) або не зустріне чанк із розміром `-1` — за специфікацією це
/// означає "дані тривають до кінця файлу" (найчастіше застосовується саме
/// до останнього, `data`-чанка).
pub fn validate_caf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"caff" {
        return None;
    }

    let mut pos = start + 8;
    let mut last_good_end: Option<usize> = None;

    while let Some(header) = data.get(pos..pos + 12) {
        let chunk_size = i64::from_be_bytes(header[4..12].try_into().ok()?);

        if chunk_size < 0 {
            return Some((data.len() - 1, 85));
        }

        let chunk_end = pos as u64 + 12 + chunk_size as u64;
        if chunk_end > data.len() as u64 {
            break;
        }

        last_good_end = Some(chunk_end as usize - 1);
        pos = chunk_end as usize;

        if pos == data.len() {
            return Some((pos - 1, 90));
        }
    }

    last_good_end.map(|end| (end, 70))
}

/// MIDI (Standard MIDI File): заголовок `MThd` вказує кількість треків
/// (`ntracks`), кожен з яких — чанк `MTrk` з явним полем довжини — проходить
/// їх усі послідовно; кінець останнього треку і є кінцем файлу.
pub fn validate_midi(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"MThd" {
        return None;
    }
    let header_len = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as usize;
    let ntracks = u16::from_be_bytes(data.get(start + 10..start + 12)?.try_into().ok()?) as usize;
    if ntracks == 0 {
        return None;
    }

    let mut pos = start + 8 + header_len;
    for _ in 0..ntracks {
        let header = data.get(pos..pos + 8)?;
        if header[0..4] != *b"MTrk" {
            return None;
        }
        let track_len = u32::from_be_bytes(header[4..8].try_into().ok()?) as u64;
        let track_end = pos as u64 + 8 + track_len;
        if track_end > data.len() as u64 {
            return None;
        }
        pos = track_end as usize;
    }

    Some((pos - 1, 90))
}

/// ProTracker MOD (варіанти `M.K.`/`FLT4`, 4 канали): заголовок фіксованого
/// розміру (1084 байти) містить довжини всіх 31 зразків (у словах) і таблицю
/// порядку відтворення патернів — звідси точно обчислюється розмір і
/// патернових даних (1024 байти на 4-канальний патерн), і всіх зразків.
pub fn validate_mod(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_LEN: u64 = 1084;
    const PATTERN_SIZE: u64 = 1024; // 4 канали × 64 рядки × 4 байти

    let sample_headers = data.get(start + 20..start + 20 + 31 * 30)?;
    let mut total_sample_bytes: u64 = 0;
    for s in sample_headers.chunks_exact(30) {
        let len_words = u16::from_be_bytes(s[22..24].try_into().ok()?) as u64;
        total_sample_bytes += len_words * 2;
    }

    let song_length = *data.get(start + 950)? as usize;
    let pattern_table = data.get(start + 952..start + 952 + 128)?;
    let num_patterns = pattern_table
        .iter()
        .take(song_length.min(128))
        .copied()
        .max()
        .map(|m| m as u64 + 1)
        .unwrap_or(0);

    let total = HEADER_LEN + num_patterns * PATTERN_SIZE + total_sample_bytes;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

fn align4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// CPIO "newc"/"crc" (сучасний ASCII-формат, зокрема initramfs): усі поля
/// заголовка — 8-символьні hex-рядки. Проходить записи (заголовок(110) +
/// ім'я, вирівняне до 4 байт + дані, вирівняні до 4 байт), доки не зустріне
/// запис `TRAILER!!!` — стандартний маркер кінця архіву.
pub fn validate_cpio_newc(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_LEN: usize = 110;

    let mut pos = start;
    loop {
        let header = data.get(pos..pos + HEADER_LEN)?;
        let namesize = usize::from_str_radix(std::str::from_utf8(&header[94..102]).ok()?, 16).ok()?;
        let filesize = usize::from_str_radix(std::str::from_utf8(&header[54..62]).ok()?, 16).ok()?;

        let name_start = pos + HEADER_LEN;
        let name = data.get(name_start..name_start + namesize)?;
        let is_trailer = name.starts_with(b"TRAILER!!!");

        let data_start = align4(name_start + namesize);
        let entry_end = align4(data_start + filesize);
        if entry_end > data.len() {
            return None;
        }

        if is_trailer {
            return Some((entry_end - 1, 90));
        }
        pos = entry_end;
    }
}

/// CPIO "odc" (старий ASCII/portable формат): поля заголовка — октальні
/// ASCII-рядки різної ширини, без вирівнювання імені/даних до 4 байт (на
/// відміну від "newc"). Та ж логіка проходу до запису `TRAILER!!!`.
pub fn validate_cpio_odc(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_LEN: usize = 76;

    let mut pos = start;
    loop {
        let header = data.get(pos..pos + HEADER_LEN)?;
        let namesize = usize::from_str_radix(std::str::from_utf8(&header[59..65]).ok()?.trim(), 8).ok()?;
        let filesize = usize::from_str_radix(std::str::from_utf8(&header[65..76]).ok()?.trim(), 8).ok()?;

        let name_start = pos + HEADER_LEN;
        let name = data.get(name_start..name_start + namesize)?;
        let is_trailer = name.starts_with(b"TRAILER!!!");

        let entry_end = name_start + namesize + filesize;
        if entry_end > data.len() {
            return None;
        }

        if is_trailer {
            return Some((entry_end - 1, 90));
        }
        pos = entry_end;
    }
}

/// Unix `ar` (статичні бібліотеки `.a`, пакунки `.deb`): проходить записи
/// (60-байтовий ASCII-заголовок з полем `size` + дані, доповнені одним
/// байтом `\n` при непарному розмірі), доки не дійде точно до кінця даних
/// (успіх) чи не зустріне заголовок без коректного маркера ``\n`` (обрізаний
/// архів чи "сміття" — повертає межу останнього повністю розібраного запису
/// з нижчою впевненістю).
pub fn validate_ar(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 8)? != b"!<arch>\n" {
        return None;
    }

    let mut pos = start + 8;
    let mut last_good_end = pos - 1;

    while let Some(header) = data.get(pos..pos + 60) {
        if header[58..60] != *b"\x60\x0a" {
            break;
        }
        let Ok(size_str) = std::str::from_utf8(&header[48..58]) else { break };
        let Ok(size) = size_str.trim().parse::<u64>() else { break };

        let mut data_end = pos as u64 + 60 + size;
        if size % 2 == 1 {
            data_end += 1;
        }
        if data_end > data.len() as u64 {
            break;
        }

        last_good_end = data_end as usize - 1;
        pos = data_end as usize;

        if pos == data.len() {
            return Some((pos - 1, 90));
        }
    }

    if last_good_end + 1 > start + 8 {
        Some((last_good_end, 70))
    } else {
        None
    }
}

/// ISO 9660 (образи CD/DVD): Primary Volume Descriptor лежить у 17-му
/// секторі (офсет 32768) і містить `Volume Space Size` (розмір у логічних
/// блоках) та `Logical Block Size` — добуток цих двох полів дає точний
/// розмір усього образу.
pub fn validate_iso9660(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const PVD_OFFSET: usize = 32768;

    let pvd = data.get(start + PVD_OFFSET..start + PVD_OFFSET + 2048)?;
    if pvd[0] != 1 || pvd[1..6] != *b"CD001" {
        return None;
    }

    let volume_space_size = u32::from_le_bytes(pvd[80..84].try_into().ok()?) as u64;
    let logical_block_size = u16::from_le_bytes(pvd[128..130].try_into().ok()?) as u64;

    let total = volume_space_size.checked_mul(logical_block_size)?;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// Zstandard: розбирає Frame_Header_Descriptor, щоб коректно пропустити всі
/// опційні поля (Window_Descriptor, Dictionary_ID, Frame_Content_Size), тоді
/// проходить послідовність Data Block'ів (кожен — 3-байтовий заголовок:
/// `last_block`-біт + тип + розмір), доки не зустріне блок із встановленим
/// `last_block`, і за потреби додає 4-байтову контрольну суму вмісту.
pub fn validate_zstd(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"\x28\xb5\x2f\xfd" {
        return None;
    }
    let fhd = *data.get(start + 4)?;
    let dict_id_flag = fhd & 0x03;
    let content_checksum_flag = fhd & 0x04 != 0;
    let single_segment_flag = fhd & 0x20 != 0;
    let fcs_flag = (fhd >> 6) & 0x03;

    let mut pos = start + 5;
    if !single_segment_flag {
        pos += 1; // Window_Descriptor
    }
    pos += match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    pos += if single_segment_flag {
        match fcs_flag {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        }
    } else {
        match fcs_flag {
            0 => 0,
            1 => 2,
            2 => 4,
            _ => 8,
        }
    };

    loop {
        let header = data.get(pos..pos + 3)?;
        let block_header = header[0] as u32 | (header[1] as u32) << 8 | (header[2] as u32) << 16;
        let last_block = block_header & 0x1 != 0;
        let block_type = (block_header >> 1) & 0x3;
        let block_size = block_header >> 3;

        if block_type == 3 {
            return None; // Reserved — недійсний блок
        }
        let block_content_len: u64 = if block_type == 1 { 1 } else { block_size as u64 };

        pos += 3 + block_content_len as usize;
        if pos > data.len() {
            return None;
        }
        if last_block {
            break;
        }
    }

    if content_checksum_flag {
        pos += 4;
    }

    let end = pos.checked_sub(1)?;
    if end >= data.len() {
        return None;
    }
    Some((end, 85))
}

/// WAD (Doom/Doom II/Heretic/Hexen — id Software): заголовок(12) містить
/// кількість "lump"-ів і офсет каталогу; кожен запис каталогу(16 байт) має
/// власні `filepos`+`size` — межа файлу є максимумом серед них і кінця
/// самого каталогу.
pub fn validate_wad(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let numlumps = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let infotableofs = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;

    let dir_start = (start as u64).checked_add(infotableofs)?;
    let dir_len = numlumps.checked_mul(16)?;
    let dir = data.get(dir_start as usize..(dir_start.checked_add(dir_len)?) as usize)?;

    let mut max_end = infotableofs + dir_len;
    for entry in dir.chunks_exact(16) {
        let filepos = u32::from_le_bytes(entry[0..4].try_into().ok()?) as u64;
        let size = u32::from_le_bytes(entry[4..8].try_into().ok()?) as u64;
        max_end = max_end.max(filepos + size);
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// PAK (Quake): та ж ідея, що й WAD — заголовок(12) вказує на каталог,
/// кожен 64-байтовий запис має власні `filepos`+`filelength`.
pub fn validate_pak_quake(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let diroffset = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let dirlen = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;

    let dir_start = (start as u64).checked_add(diroffset)?;
    let dir = data.get(dir_start as usize..(dir_start.checked_add(dirlen)?) as usize)?;

    let mut max_end = diroffset + dirlen;
    for entry in dir.chunks_exact(64) {
        let filepos = u32::from_le_bytes(entry[56..60].try_into().ok()?) as u64;
        let filelength = u32::from_le_bytes(entry[60..64].try_into().ok()?) as u64;
        max_end = max_end.max(filepos + filelength);
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// VBSP (Source engine — Half-Life 2, CS:S, Portal, TF2, L4D тощо): 17
/// записів таблиці "lump"-ів (по 16 байт: `fileofs`+`filelen`+`version`+
/// `fourCC`) — межа файлу є максимумом `fileofs+filelen` серед них.
pub fn validate_vbsp(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const NUM_LUMPS: usize = 17;
    const HEADER_LEN: u64 = 8 + NUM_LUMPS as u64 * 16;

    let lumps_start = start + 8;
    let lumps = data.get(lumps_start..lumps_start + NUM_LUMPS * 16)?;

    let mut max_end = HEADER_LEN;
    for lump in lumps.chunks_exact(16) {
        let fileofs = u32::from_le_bytes(lump[0..4].try_into().ok()?) as u64;
        let filelen = u32::from_le_bytes(lump[4..8].try_into().ok()?) as u64;
        max_end = max_end.max(fileofs + filelen);
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 80))
}

/// NES (iNES ROM): 16-байтовий заголовок прямо містить розміри PRG/CHR ROM
/// (в одиницях 16 KiB/8 KiB відповідно) і прапорець наявності 512-байтового
/// trainer-блоку — усе, що потрібно для точного розрахунку розміру файлу.
/// (Розширення NES 2.0 з іншим кодуванням розміру не враховується — для
/// таких ROM валідатор просто не спрацює і сканер відкотиться до евристики.)
pub fn validate_nes(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let prg_units = *data.get(start + 4)? as u64;
    let chr_units = *data.get(start + 5)? as u64;
    let flags6 = *data.get(start + 6)?;
    let trainer: u64 = if flags6 & 0x04 != 0 { 512 } else { 0 };

    let total = 16 + trainer + prg_units * 16384 + chr_units * 8192;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

/// UnityFS (Unity Asset Bundle): після сигнатури йдуть версія(4) і дві
/// NUL-терміновані рядкові поля змінної довжини (`unityVersion`,
/// `unityRevision`), а тоді — поле `size`(8, знакове, big-endian), що прямо
/// містить точний розмір усього бандла.
pub fn validate_unityfs(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let mut pos = start + 8; // після сигнатури "UnityFS\0"
    pos += 4; // version (не потрібне для розрахунку)

    for _ in 0..2 {
        let rel = memchr::memchr(0, data.get(pos..)?)?;
        pos += rel + 1;
    }

    let size = i64::from_be_bytes(data.get(pos..pos + 8)?.try_into().ok()?);
    if size < 0 {
        return None;
    }
    let end = (start as u64).checked_add(size as u64)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// VPK v2 (Source engine — CS:GO, TF2, Dota 2, HL2, Portal): усі розміри
/// секцій, що йдуть одразу після 28-байтового заголовка (дерево каталогу +
/// дані файлів + MD5-секції + підпис), прямо вказані в самому заголовку.
/// VPK v1 (лише 12-байтовий заголовок, без цих полів) не підтримується —
/// валідатор просто не спрацює.
pub fn validate_vpk(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let version = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?);
    if version != 2 {
        return None;
    }

    let tree_size = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;
    let file_data_size = u32::from_le_bytes(data.get(start + 12..start + 16)?.try_into().ok()?) as u64;
    let archive_md5_size = u32::from_le_bytes(data.get(start + 16..start + 20)?.try_into().ok()?) as u64;
    let other_md5_size = u32::from_le_bytes(data.get(start + 20..start + 24)?.try_into().ok()?) as u64;
    let signature_size = u32::from_le_bytes(data.get(start + 24..start + 28)?.try_into().ok()?) as u64;

    let total = 28 + tree_size + file_data_size + archive_md5_size + other_md5_size + signature_size;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

/// Пропускає zlib-потік (2-байтовий заголовок + DEFLATE + 4-байтовий
/// Adler32), повертаючи кількість спожитих вхідних байтів. На відміну від
/// [`deflate_stream_len`] (raw DEFLATE, використовується GZIP), тут потрібен
/// саме zlib-формат — його використовує стиснений SWF (`CWS`).
fn zlib_stream_len(input: &[u8]) -> Option<usize> {
    let mut decompress = flate2::Decompress::new(true);
    let mut out = vec![0u8; 64 * 1024];

    loop {
        let before_in = decompress.total_in();
        let before_out = decompress.total_out();
        let consumed_so_far = before_in as usize;
        let status = decompress
            .decompress(&input[consumed_so_far..], &mut out, flate2::FlushDecompress::None)
            .ok()?;

        match status {
            flate2::Status::StreamEnd => return Some(decompress.total_in() as usize),
            flate2::Status::Ok => {
                let made_progress = decompress.total_in() > before_in || decompress.total_out() > before_out;
                if !made_progress || decompress.total_out() > MAX_GZIP_DECOMPRESS_BYTES {
                    return None;
                }
            }
            flate2::Status::BufError => return None,
        }
    }
}

/// SWF (Adobe/Macromedia Flash, застарілий застосунками — знято з підтримки
/// браузерами 2021 р.): `FWS` (нестиснений) прямо містить `FileLength` у
/// заголовку. `CWS` (zlib-стиснений) вимагає розпакування тіла, щоб
/// дізнатися його реальну довжину на диску (поле `FileLength` там — розмір
/// уже РОЗпакованих даних, не корисний для меж на диску). `ZWS`
/// (LZMA-стиснений) не підтримується — немає LZMA-декодера серед
/// залежностей, тож валідатор відмовляється, і сканер відкочується до
/// евристики.
pub fn validate_swf(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let sig = data.get(start..start + 3)?;
    let file_length = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;

    match sig {
        b"FWS" => {
            let end = (start as u64).checked_add(file_length)?.checked_sub(1)?;
            if end >= data.len() as u64 {
                return None;
            }
            Some((end as usize, 95))
        }
        b"CWS" => {
            let body_len = zlib_stream_len(data.get(start + 8..)?)? as u64;
            let end = (start as u64).checked_add(8)?.checked_add(body_len)?.checked_sub(1)?;
            if end >= data.len() as u64 {
                return None;
            }
            Some((end as usize, 90))
        }
        _ => None,
    }
}

/// RIFX (Macromedia/Adobe Shockwave Director — застарілий, замінений
/// HTML5): той самий принцип, що й RIFF/IFF, але сигнатура `RIFX` і
/// big-endian розмір, оскільки формат історично використовувався
/// однаково на Mac (big-endian) і Windows.
pub fn validate_rifx(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"RIFX" {
        return None;
    }
    let chunk_size = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(8)?.checked_add(chunk_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// RealMedia (`.rm`/`.ra` — RealNetworks, застарілий стрімінговий формат
/// кінця 1990-х/2000-х): початковий чанк `.RMF` вказує `num_headers` —
/// кількість топ-рівневих чанків у файлі; проходить решту (кожен —
/// `id`(4)+`size`(4,BE)+`version`(2)+дані) за їхніми власними полями
/// розміру.
pub fn validate_realmedia(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b".RMF" {
        return None;
    }
    let rmf_size = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let num_headers = u32::from_be_bytes(data.get(start + 14..start + 18)?.try_into().ok()?) as usize;
    if rmf_size < 18 || num_headers == 0 {
        return None;
    }

    let mut pos = start as u64 + rmf_size;
    for _ in 1..num_headers {
        let header = data.get(pos as usize..pos as usize + 10)?;
        let size = u32::from_be_bytes(header[4..8].try_into().ok()?) as u64;
        if size < 10 {
            return None;
        }
        pos += size;
    }

    let end = pos.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 80))
}

/// VOC (Creative Voice File — формат Sound Blaster для DOS, застарілий):
/// проходить послідовність блоків (`block_type`(1)+`block_size`(3,LE,
/// 24-бітний) + дані), доки не зустріне термінуючий блок типу 0 (без
/// власного поля розміру) або кінець даних.
pub fn validate_voc(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const MAGIC: &[u8] = b"Creative Voice File\x1a";

    if data.get(start..start + MAGIC.len())? != MAGIC {
        return None;
    }
    let header_size = u16::from_le_bytes(data.get(start + 20..start + 22)?.try_into().ok()?) as u64;

    let mut pos = start as u64 + header_size;
    loop {
        let block_type = *data.get(pos as usize)?;
        if block_type == 0 {
            pos += 1; // Terminator: лише байт типу, без поля розміру
            break;
        }
        let size_bytes = data.get(pos as usize + 1..pos as usize + 4)?;
        let block_size = size_bytes[0] as u64 | (size_bytes[1] as u64) << 8 | (size_bytes[2] as u64) << 16;
        pos += 4 + block_size;
        if pos > data.len() as u64 {
            return None;
        }
    }

    let end = pos.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

/// Читає EBML VINT (variable-length integer): кількість провідних нульових
/// бітів першого байта визначає загальну довжину (1-8 байт), решта бітів —
/// значення. Повертає `(значення, довжина_у_байтах)`.
fn read_ebml_vint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if len > 8 || data.len() < len {
        return None;
    }
    // len==8 означає, що маркерний біт займає весь перший байт (0x01) — усі
    // дані йдуть із решти 7 байтів; `0xFF >> 8` для u8 panic'ає (зсув на
    // всю ширину типу), тож цей випадок виділяємо окремо.
    let mask: u8 = if len == 8 { 0 } else { 0xFFu8 >> len };
    let mut value = (first & mask) as u64;
    for &b in &data[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

/// EBML/Matroska (охоплює і MKV, і WebM — це той самий контейнер, WebM є
/// лише профілем-обмеженням Matroska з тими самими магічними байтами):
/// пропускає EBML-заголовок, тоді читає розмір елемента `Segment` — той і
/// дає точну межу файлу. "Невідомий розмір" (усі використовні біти VINT
/// встановлені в 1 — типово для потокових/наживо записаних файлів) не
/// підтримується: точний кінець вимагав би повного обходу вкладених
/// елементів, тож валідатор відмовляється, і сканер відкочується до
/// евристики.
pub fn validate_ebml(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"\x1a\x45\xdf\xa3" {
        return None;
    }
    let (header_size, header_size_len) = read_ebml_vint(data.get(start + 4..)?)?;
    let mut pos = start + 4 + header_size_len + header_size as usize;

    if data.get(pos..pos + 4)? != b"\x18\x53\x80\x67" {
        return None;
    }
    pos += 4;
    let (segment_size, segment_size_len) = read_ebml_vint(data.get(pos..)?)?;
    pos += segment_size_len;

    let usable_bits = 7 * segment_size_len as u32;
    let unknown_marker = if usable_bits >= 64 { u64::MAX } else { (1u64 << usable_bits) - 1 };
    if segment_size == unknown_marker {
        return None;
    }

    let end = (pos as u64).checked_add(segment_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// FLV (Flash Video): проходить послідовність тегів (кожному передує
/// 4-байтове поле `PreviousTagSize`, за ним 11-байтовий заголовок тега з
/// власним `DataSize`), доки не дійде точно до фінального трейлера в кінці
/// файлу (успіх) або не зустріне обрізаний/недійсний тег (повертає межу
/// останнього повністю розібраного тега з нижчою впевненістю).
pub fn validate_flv(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 3)? != b"FLV" {
        return None;
    }
    let header_size = u32::from_be_bytes(data.get(start + 5..start + 9)?.try_into().ok()?) as usize;

    let mut pos = start + header_size;
    let mut last_good_end = pos.checked_sub(1)?;

    loop {
        if data.get(pos..pos + 4).is_none() {
            break;
        }
        let tag_pos = pos + 4;
        let Some(tag_header) = data.get(tag_pos..tag_pos + 11) else {
            if pos + 4 == data.len() {
                return Some((data.len() - 1, 90));
            }
            break;
        };
        let data_size = u32::from_be_bytes([0, tag_header[1], tag_header[2], tag_header[3]]) as usize;
        let tag_end = tag_pos + 11 + data_size;
        if tag_end > data.len() {
            break;
        }

        last_good_end = tag_end - 1;
        pos = tag_end;
    }

    if last_good_end + 1 > start + header_size {
        Some((last_good_end, 70))
    } else {
        None
    }
}

/// Обрізає байти по першому NUL (характерно для C-рядків у бінарних
/// заголовках — TAR/CPIO/WAD/PAK) і прибирає пробіли з кінця (характерно
/// для текстових ASCII-полів — `ar`), повертаючи `None`, якщо результат
/// порожній.
fn bytes_to_trimmed_string(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// TAR: ім'я файлу — поле `name`(100 байт); якщо задане POSIX-поле
/// `prefix`(155 байт, офсет 345) для довгих шляхів, повний шлях —
/// `prefix/name`.
pub fn extract_tar_name(data: &[u8], start: usize) -> Option<String> {
    let header = data.get(start..start + 512)?;
    let name = bytes_to_trimmed_string(&header[0..100])?;
    match bytes_to_trimmed_string(&header[345..500]) {
        Some(prefix) => Some(format!("{prefix}/{name}")),
        None => Some(name),
    }
}

/// CPIO "newc"/"crc": ім'я лежить одразу після 110-байтового заголовка,
/// довжина — у полі `c_namesize` (hex ASCII, включно з NUL-термінатором).
pub fn extract_cpio_newc_name(data: &[u8], start: usize) -> Option<String> {
    let header = data.get(start..start + 110)?;
    let namesize = usize::from_str_radix(std::str::from_utf8(&header[94..102]).ok()?, 16).ok()?;
    let name = data.get(start + 110..start + 110 + namesize)?;
    bytes_to_trimmed_string(name)
}

/// CPIO "odc": та ж ідея, але заголовок 76 байт і `namesize` — октальний
/// ASCII.
pub fn extract_cpio_odc_name(data: &[u8], start: usize) -> Option<String> {
    let header = data.get(start..start + 76)?;
    let namesize = usize::from_str_radix(std::str::from_utf8(&header[59..65]).ok()?.trim(), 8).ok()?;
    let name = data.get(start + 76..start + 76 + namesize)?;
    bytes_to_trimmed_string(name)
}

/// Unix `ar`: ім'я першого запису одразу після глобального заголовка
/// `!<arch>\n` (16-байтове, доповнене пробілами). Символьні псевдо-записи
/// GNU-таблиці символів/довгих імен (`/`, `//`) повертаються буквально —
/// це справжнє ім'я цього конкретного запису, просто не файлу користувача.
pub fn extract_ar_name(data: &[u8], start: usize) -> Option<String> {
    let entry_name = data.get(start + 8..start + 8 + 16)?;
    bytes_to_trimmed_string(entry_name)
}

/// WAD: ім'я першого lump'а, переліченого в каталозі (за `infotableofs`) —
/// не першого за фізичним розташуванням даних, а першого в самій таблиці.
pub fn extract_wad_name(data: &[u8], start: usize) -> Option<String> {
    let infotableofs = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as usize;
    let entry = data.get(start + infotableofs..start + infotableofs + 16)?;
    bytes_to_trimmed_string(&entry[8..16])
}

/// PAK (Quake): ім'я першого файлу, переліченого в каталозі (за
/// `diroffset`).
pub fn extract_pak_name(data: &[u8], start: usize) -> Option<String> {
    let diroffset = u32::from_le_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as usize;
    let entry = data.get(start + diroffset..start + diroffset + 56)?;
    bytes_to_trimmed_string(entry)
}

/// WOFF/WOFF2 (веб-шрифти): поле `length` (offset 8, 4 байти BE) прямо
/// містить точний розмір усього файлу — та ж позиція й семантика в обох
/// версіях формату.
pub fn validate_woff(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let length = u32::from_be_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(length)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// glTF Binary (.glb): 12-байтовий заголовок (`magic`+`version`+`length`)
/// має поле `length` — точний розмір усього файлу.
pub fn validate_glb(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 4)? != b"glTF" {
        return None;
    }
    let length = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(length)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// MPQ (архіви Blizzard — Warcraft III, StarCraft, Diablo, World of
/// Warcraft): поле `ArchiveSize` у заголовку v1 (офсет 8, 4 байти LE) прямо
/// містить точний розмір архіву.
pub fn validate_mpq(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let archive_size = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(archive_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 85))
}

/// SquashFS: поле `bytes_used` у суперблоці (офсет 40, 8 байт LE) прямо
/// містить точний розмір усього образу файлової системи.
pub fn validate_squashfs(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let bytes_used = u64::from_le_bytes(data.get(start + 40..start + 48)?.try_into().ok()?);
    let end = (start as u64).checked_add(bytes_used)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// CAB (Microsoft Cabinet): поле `cbCabinet` у заголовку (офсет 8, 4 байти
/// LE) прямо містить точний розмір усього файлу кабінету.
pub fn validate_cab(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let cb_cabinet = u32::from_le_bytes(data.get(start + 8..start + 12)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(cb_cabinet)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// DEX (Android Dalvik executable, `classes.dex` усередині кожного APK):
/// поле `file_size` у заголовку (офсет 32, 4 байти LE) прямо містить точний
/// розмір усього файлу.
pub fn validate_dex(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let file_size = u32::from_le_bytes(data.get(start + 32..start + 36)?.try_into().ok()?) as u64;
    let end = (start as u64).checked_add(file_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// DPX (Digital Picture Exchange, кіноіндустрія): поле `file_size` у
/// заголовку (офсет 16, 4 байти — порядок байтів визначається тим, який
/// варіант сигнатури спрацював, `SDPX`=big-endian чи `XPDS`=little-endian)
/// прямо містить точний розмір усього файлу.
pub fn validate_dpx(data: &[u8], start: usize, is_be: bool) -> Option<(usize, u8)> {
    let bytes = data.get(start + 16..start + 20)?;
    let file_size = if is_be {
        u32::from_be_bytes(bytes.try_into().ok()?)
    } else {
        u32::from_le_bytes(bytes.try_into().ok()?)
    } as u64;
    let end = (start as u64).checked_add(file_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

pub fn validate_dpx_be(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_dpx(data, start, true)
}

pub fn validate_dpx_le(data: &[u8], start: usize) -> Option<(usize, u8)> {
    validate_dpx(data, start, false)
}

/// ICC-профіль кольору: сигнатура `acsp` лежить за офсетом 36 від початку
/// профілю, а саме поле `profile_size` (офсет 0, 4 байти BE) — на самому
/// початку — прямо містить точний розмір усього файлу.
pub fn validate_icc(data: &[u8], start: usize) -> Option<(usize, u8)> {
    const HEADER_LEN: u64 = 128; // ICC-заголовок має фіксований розмір 128 байт (специфікація ICC.1)

    let profile_size = u32::from_be_bytes(data.get(start..start + 4)?.try_into().ok()?) as u64;
    // profile_size включає сам заголовок — менше значення означає сміттєвий
    // збіг, а не справжній ICC-профіль (інакше end < start, underflow).
    if profile_size < HEADER_LEN {
        return None;
    }
    let end = (start as u64).checked_add(profile_size)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// AppleSingle/AppleDouble (кодування ресурсної гілки класичного Mac OS;
/// саме в цьому форматі macOS досі зберігає метадані у файлах `._ім'я` на
/// не-HFS+ файлових системах): за 26-байтовим заголовком іде масив записів
/// `id`(4)+`offset`(4)+`length`(4) по 12 байт — межа файлу є максимумом
/// `offset+length` серед них.
pub fn validate_apple_single_double(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let num_entries = u16::from_be_bytes(data.get(start + 24..start + 26)?.try_into().ok()?) as usize;
    if num_entries == 0 {
        return None;
    }
    let entries = data.get(start + 26..start + 26 + num_entries * 12)?;

    let mut max_end: u64 = 0;
    for entry in entries.chunks_exact(12) {
        let offset = u32::from_be_bytes(entry[4..8].try_into().ok()?) as u64;
        let length = u32::from_be_bytes(entry[8..12].try_into().ok()?) as u64;
        max_end = max_end.max(offset + length);
    }
    if max_end == 0 {
        return None;
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// Blender `.blend`: проходить послідовність файлових блоків (`code`(4)+
/// `size`(4, порядок байтів — з прапорця у заголовку)+`old_address`(4 чи 8
/// байт, залежно від розрядності)+`SDNAindex`(4)+`count`(4)+дані), доки не
/// зустріне блок `ENDB` — стандартний термінатор.
pub fn validate_blend(data: &[u8], start: usize) -> Option<(usize, u8)> {
    if data.get(start..start + 7)? != b"BLENDER" {
        return None;
    }
    let ptr_size: usize = match *data.get(start + 7)? {
        b'_' => 4,
        b'-' => 8,
        _ => return None,
    };
    let is_be = match *data.get(start + 8)? {
        b'v' => false,
        b'V' => true,
        _ => return None,
    };

    let mut pos = start + 12;
    loop {
        let code = data.get(pos..pos + 4)?;
        let size_bytes = data.get(pos + 4..pos + 8)?;
        let size = if is_be {
            u32::from_be_bytes(size_bytes.try_into().ok()?)
        } else {
            u32::from_le_bytes(size_bytes.try_into().ok()?)
        } as usize;

        let header_len = 8 + ptr_size + 8;
        let block_end = pos.checked_add(header_len)?.checked_add(size)?;
        if block_end > data.len() {
            return None;
        }

        if code == b"ENDB" {
            let end = block_end.checked_sub(1)?;
            if end < start {
                return None;
            }
            return Some((end, 85));
        }
        pos = block_end;
    }
}

/// AU (Sun/NeXT audio): поля `data_offset`+`data_size` в заголовку (обидва
/// BE) прямо дають точний розмір усього файлу. `data_size` рівний
/// `0xFFFFFFFF` означає "невідомий розмір" (потокові записи) — тоді
/// валідатор відмовляється.
pub fn validate_au(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let data_offset = u32::from_be_bytes(data.get(start + 4..start + 8)?.try_into().ok()?) as u64;
    let data_size = u32::from_be_bytes(data.get(start + 8..start + 12)?.try_into().ok()?);
    if data_size == 0xFFFFFFFF {
        return None;
    }
    let total = data_offset + data_size as u64;
    let end = (start as u64).checked_add(total)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// TTF/OTF (sfnt-контейнер, спільний для обох): перевіряє математичні
/// інваріанти заголовка (`searchRange`/`entrySelector`/`rangeShift` — усі
/// три виводяться з `numTables` за формулою зі специфікації OpenType) —
/// випадкові байти в довільних бінарних даних майже ніколи не задовольняють
/// усі три одночасно, тож це ефективний фільтр хибних збігів на 4-байтову
/// сигнатуру. Якщо інваріанти виконуються, таблиця директорії (по 16 байт
/// на таблицю) дає точну межу файлу — максимум `offset+length` серед усіх
/// таблиць.
pub fn validate_sfnt(data: &[u8], start: usize) -> Option<(usize, u8)> {
    let num_tables = u16::from_be_bytes(data.get(start + 4..start + 6)?.try_into().ok()?);
    if num_tables == 0 || num_tables > 100 {
        return None; // нереалістична кількість таблиць для справжнього шрифту
    }

    let search_range = u16::from_be_bytes(data.get(start + 6..start + 8)?.try_into().ok()?);
    let entry_selector = u16::from_be_bytes(data.get(start + 8..start + 10)?.try_into().ok()?);

    // rangeShift навмисно НЕ перевіряється: попри те, що специфікація
    // OpenType визначає його як `numTables*16 - searchRange`, на практиці
    // чимало реальних шрифтів (у т.ч. системні шрифти Apple) містять
    // некоректне значення цього поля — жоден парсер на нього не покладається,
    // тож генератори шрифтів часто його неправильно обчислюють чи лишають
    // застарілим. Сувора перевірка відхиляла б справжні шрифти.
    let expected_entry_selector = 15 - (num_tables | 1).leading_zeros() as u16; // floor(log2(num_tables))
    let expected_search_range = (1u16 << expected_entry_selector).wrapping_mul(16);

    if search_range != expected_search_range || entry_selector != expected_entry_selector {
        return None;
    }

    let table_dir_start = start + 12;
    let table_dir = data.get(table_dir_start..table_dir_start + num_tables as usize * 16)?;

    let mut max_end: u64 = 12 + num_tables as u64 * 16;
    for entry in table_dir.chunks_exact(16) {
        let offset = u32::from_be_bytes(entry[8..12].try_into().ok()?) as u64;
        let length = u32::from_be_bytes(entry[12..16].try_into().ok()?) as u64;
        max_end = max_end.max(offset + length);
    }

    let end = (start as u64).checked_add(max_end)?.checked_sub(1)?;
    if end >= data.len() as u64 {
        return None;
    }
    Some((end as usize, 90))
}

/// Один запис у структурному переліку знахідки — ім'я (файлу, чанку, боксу,
/// таблиці шрифту чи секції виконуваного файлу) та розмір, як заявлено в
/// самому заголовку контейнера.
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
}

/// Будує повний структурний перелік усередині знахідки (для показу в TUI
/// замість/на додачу до hex-перегляду) — на відміну від `NameExtractor`, що
/// витягує лише ОДНЕ (перше) ім'я для підказки в списку знахідок. Охоплює не
/// лише "справжні" архіви з файлами (ZIP/TAR/CPIO/AR/WAD/PAK), а й будь-який
/// формат із внутрішньою структурою запис-за-записом: таблиці sfnt-шрифтів,
/// чанки PNG-родини/RIFF/IFF, бокси ISOBMFF, секції ELF/PE/Mach-O.
/// `fragment` — уже вирізаний байтовий діапазон самої знахідки (офсет 0 у
/// ньому відповідає початку контейнера). Повертає `None`, якщо формат не
/// підтримує такий перелік, або якщо структуру не вдалося розібрати.
pub fn list_archive_entries(format: &str, fragment: &[u8]) -> Option<Vec<ArchiveEntry>> {
    match format {
        "ZIP" => list_zip_entries(fragment),
        "TAR" => list_tar_entries(fragment),
        "CPIO-newc" | "CPIO-crc" => list_cpio_newc_entries(fragment),
        "CPIO-odc" => list_cpio_odc_entries(fragment),
        "AR" => list_ar_entries(fragment),
        "WAD-I" | "WAD-P" => list_wad_entries(fragment),
        "PAK-Quake" => list_pak_entries(fragment),
        "TTF" | "OTF" => list_sfnt_tables(fragment),
        "PNG" => list_png_chunks(fragment, b"\x89PNG\r\n\x1a\n"),
        "MNG" => list_png_chunks(fragment, b"\x8aMNG\r\n\x1a\n"),
        "JNG" => list_png_chunks(fragment, b"\x8bJNG\r\n\x1a\n"),
        "WAV" | "AVI" | "WEBP" | "CDR" | "ANI" | "RMID" | "RIFF-PAL" | "RDIB" => list_riff_chunks(fragment),
        "AIFF" | "AIFC" | "8SVX" | "ILBM" | "ANIM" | "ANBM" => list_iff_chunks(fragment),
        "MP4-isom" | "MP4-mp42" | "MP4-mp41" | "MP4-avc1" | "MP4-iso2" | "MOV" | "M4A" | "M4B" | "M4P" | "3GP"
        | "3G2" | "3GP-3gp5" | "M4V" | "HEIC" | "HEIC-10bit" | "AVIF" | "AVIF-sequence" | "HEIF-mif1"
        | "HEIF-msf1" | "HEIF-heis" | "HEIF-hevc" | "JP2" | "JXL" => list_isobmff_boxes(fragment),
        "ELF" => list_elf_sections(fragment),
        "PE" => list_pe_sections(fragment),
        "Mach-O-32-BE" => list_macho_sections(fragment, false, true),
        "Mach-O-32-LE" => list_macho_sections(fragment, false, false),
        "Mach-O-64-BE" => list_macho_sections(fragment, true, true),
        "Mach-O-64-LE" => list_macho_sections(fragment, true, false),
        "Mach-O-Fat" => list_macho_fat_archs(fragment),
        "SQLite" => list_sqlite_entries(fragment),
        "ISO9660" => list_iso9660_entries(fragment),
        "VPK" => list_vpk_entries(fragment),
        "RAR" => list_rar_entries(fragment),
        _ => None,
    }
}

/// Той самий прохід локальними заголовками, що й `validate_zip`, але замість
/// лише обчислення межі — збирає ім'я й нестиснений розмір кожного запису.
fn list_zip_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const LOCAL_SIG: &[u8] = b"PK\x03\x04";
    const DATA_DESCRIPTOR_FLAG: u16 = 1 << 3;

    let mut pos = 0;
    let mut entries = Vec::new();

    while data.get(pos..pos + 4)? == LOCAL_SIG {
        let flags = u16::from_le_bytes(data.get(pos + 6..pos + 8)?.try_into().ok()?);
        let compressed_size = u32::from_le_bytes(data.get(pos + 18..pos + 22)?.try_into().ok()?) as usize;
        let uncompressed_size = u32::from_le_bytes(data.get(pos + 22..pos + 26)?.try_into().ok()?) as u64;
        let name_len = u16::from_le_bytes(data.get(pos + 26..pos + 28)?.try_into().ok()?) as usize;
        let extra_len = u16::from_le_bytes(data.get(pos + 28..pos + 30)?.try_into().ok()?) as usize;

        let name_start = pos + 30;
        let name = String::from_utf8_lossy(data.get(name_start..name_start + name_len)?).into_owned();
        let header_end = name_start + name_len + extra_len;

        entries.push(ArchiveEntry { name, size: uncompressed_size });

        pos = if flags & DATA_DESCRIPTOR_FLAG != 0 {
            find_next_pk_marker(data, header_end)?
        } else {
            header_end + compressed_size
        };
        if pos > data.len() {
            break;
        }
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід 512-байтовими блоками, що й `validate_tar`, але збирає
/// ім'я й розмір кожного запису замість лише межі останнього.
fn list_tar_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const BLOCK: usize = 512;
    let mut pos = 0;
    let mut entries = Vec::new();

    while let Some(header) = data.get(pos..pos + BLOCK) {
        if header.iter().all(|&b| b == 0) || &header[257..262] != b"ustar" {
            break;
        }
        let size = match parse_octal(&header[124..136]) {
            Some(size) if header[124] & 0x80 == 0 => size,
            _ => break,
        };
        let name = bytes_to_trimmed_string(&header[0..100]).unwrap_or_default();
        entries.push(ArchiveEntry { name, size });

        let data_blocks = (size as usize).div_ceil(BLOCK);
        pos += BLOCK + data_blocks * BLOCK;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід записами, що й `validate_cpio_newc`, але збирає ім'я й
/// розмір кожного файлу до самого `TRAILER!!!` замість лише межі архіву.
fn list_cpio_newc_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const HEADER_LEN: usize = 110;
    let mut pos = 0;
    let mut entries = Vec::new();

    loop {
        let header = data.get(pos..pos + HEADER_LEN)?;
        let namesize = usize::from_str_radix(std::str::from_utf8(&header[94..102]).ok()?, 16).ok()?;
        let filesize = usize::from_str_radix(std::str::from_utf8(&header[54..62]).ok()?, 16).ok()? as u64;

        let name_start = pos + HEADER_LEN;
        let name_bytes = data.get(name_start..name_start + namesize)?;
        if name_bytes.starts_with(b"TRAILER!!!") {
            break;
        }

        let data_start = align4(name_start + namesize);
        let entry_end = align4(data_start + filesize as usize);
        if entry_end > data.len() {
            break;
        }
        entries.push(ArchiveEntry {
            name: bytes_to_trimmed_string(name_bytes).unwrap_or_default(),
            size: filesize,
        });
        pos = entry_end;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід записами, що й `validate_cpio_odc` (без вирівнювання
/// до 4 байт, на відміну від "newc").
fn list_cpio_odc_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const HEADER_LEN: usize = 76;
    let mut pos = 0;
    let mut entries = Vec::new();

    loop {
        let header = data.get(pos..pos + HEADER_LEN)?;
        let namesize = usize::from_str_radix(std::str::from_utf8(&header[59..65]).ok()?.trim(), 8).ok()?;
        let filesize = usize::from_str_radix(std::str::from_utf8(&header[65..76]).ok()?.trim(), 8).ok()? as u64;

        let name_start = pos + HEADER_LEN;
        let name_bytes = data.get(name_start..name_start + namesize)?;
        if name_bytes.starts_with(b"TRAILER!!!") {
            break;
        }

        let entry_end = name_start + namesize + filesize as usize;
        if entry_end > data.len() {
            break;
        }
        entries.push(ArchiveEntry {
            name: bytes_to_trimmed_string(name_bytes).unwrap_or_default(),
            size: filesize,
        });
        pos = entry_end;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід записами, що й `validate_ar`. Довгі імена GNU-розширення
/// (`/0`, `/17`, що посилаються на таблицю `//`) не розвертаються в реальне
/// ім'я — показуються буквально, як і в `extract_ar_name`.
fn list_ar_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    if data.get(0..8)? != b"!<arch>\n" {
        return None;
    }

    let mut pos = 8;
    let mut entries = Vec::new();

    while let Some(header) = data.get(pos..pos + 60) {
        if header[58..60] != *b"\x60\x0a" {
            break;
        }
        let Ok(size_str) = std::str::from_utf8(&header[48..58]) else { break };
        let Ok(size) = size_str.trim().parse::<u64>() else { break };

        entries.push(ArchiveEntry {
            name: bytes_to_trimmed_string(&header[0..16]).unwrap_or_default(),
            size,
        });

        let mut data_end = pos as u64 + 60 + size;
        if size % 2 == 1 {
            data_end += 1;
        }
        if data_end > data.len() as u64 {
            break;
        }
        pos = data_end as usize;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Каталог лампів WAD (16-байтові записи: `filepos`+`size`+8-байтове ім'я) —
/// та сама структура, що й у `validate_wad`/`extract_wad_name`, але для
/// ВСІХ записів каталогу, а не лише першого.
fn list_wad_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let numlumps = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let infotableofs = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?) as usize;

    let dir = data.get(infotableofs..infotableofs.checked_add(numlumps.checked_mul(16)?)?)?;
    let mut entries = Vec::with_capacity(numlumps);
    for entry in dir.chunks_exact(16) {
        entries.push(ArchiveEntry {
            name: bytes_to_trimmed_string(&entry[8..16]).unwrap_or_default(),
            size: u32::from_le_bytes(entry[4..8].try_into().ok()?) as u64,
        });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Каталог PAK (Quake, 64-байтові записи: 56-байтове ім'я + `filepos`+
/// `filelength`) — та сама структура, що й у `validate_pak_quake`, для
/// ВСІХ записів каталогу.
fn list_pak_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let diroffset = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let dirlen = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?) as usize;

    let dir = data.get(diroffset..diroffset.checked_add(dirlen)?)?;
    let mut entries = Vec::new();
    for entry in dir.chunks_exact(64) {
        entries.push(ArchiveEntry {
            name: bytes_to_trimmed_string(&entry[0..56]).unwrap_or_default(),
            size: u32::from_le_bytes(entry[60..64].try_into().ok()?) as u64,
        });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід таблицею директорії, що й `validate_sfnt`, але збирає
/// тег і довжину кожної таблиці (`cmap`, `glyf`, `head`...) замість лише межі.
fn list_sfnt_tables(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let num_tables = u16::from_be_bytes(data.get(4..6)?.try_into().ok()?) as usize;
    if num_tables == 0 || num_tables > 100 {
        return None;
    }
    let table_dir = data.get(12..12 + num_tables * 16)?;

    let mut entries = Vec::with_capacity(num_tables);
    for entry in table_dir.chunks_exact(16) {
        let length = u32::from_be_bytes(entry[12..16].try_into().ok()?) as u64;
        entries.push(ArchiveEntry {
            name: String::from_utf8_lossy(&entry[0..4]).into_owned(),
            size: length,
        });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Той самий прохід чанками, що й `validate_png_family`, але збирає тип і
/// довжину кожного чанку (`IHDR`, `IDAT`, `PLTE`...) замість лише межі файлу.
fn list_png_chunks(data: &[u8], signature: &[u8]) -> Option<Vec<ArchiveEntry>> {
    if data.get(0..signature.len())? != signature {
        return None;
    }

    let mut pos = signature.len();
    let mut entries = Vec::new();
    loop {
        let length = u32::from_be_bytes(data.get(pos..pos + 4)?.try_into().ok()?) as usize;
        let chunk_type = data.get(pos + 4..pos + 8)?;
        let chunk_end = pos + 8 + length + 4; // length + type(4) + data(length) + crc(4)
        if chunk_end > data.len() {
            break;
        }

        entries.push(ArchiveEntry {
            name: String::from_utf8_lossy(chunk_type).into_owned(),
            size: length as u64,
        });

        pos = chunk_end;
        if pos >= data.len() {
            break;
        }
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Спільна логіка для RIFF (little-endian, `RIFF`+size+formType) та Amiga IFF
/// (big-endian, `FORM`+size+formType) — обидва мають ідентичну структуру
/// підчанків (`id`(4)+`size`(4)+дані, доповнені до парного розміру), що
/// відрізняється лише порядком байтів поля розміру.
fn list_chunk_container(data: &[u8], is_be: bool) -> Option<Vec<ArchiveEntry>> {
    let read_u32 = |b: &[u8]| -> Option<u32> {
        let b: [u8; 4] = b.try_into().ok()?;
        Some(if is_be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    };

    let total_size = read_u32(data.get(4..8)?)? as usize;
    let container_end = (8usize.checked_add(total_size)?).min(data.len());

    let mut pos: usize = 12; // після tag(4) + size(4) + formType(4)
    let mut entries = Vec::new();
    while pos.checked_add(8)? <= container_end {
        let chunk_id = data.get(pos..pos + 4)?;
        let chunk_size = read_u32(data.get(pos + 4..pos + 8)?)? as usize;

        // Пробіл у 4-байтовому ID — значуща частина самого ідентифікатора
        // (напр. `"fmt "` у WAV), а не padding, тож на відміну від
        // C-рядкових імен деінде тут НЕ обрізається.
        entries.push(ArchiveEntry {
            name: String::from_utf8_lossy(chunk_id).into_owned(),
            size: chunk_size as u64,
        });

        let padded = chunk_size + chunk_size % 2;
        pos = pos.checked_add(8)?.checked_add(padded)?;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

fn list_riff_chunks(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    list_chunk_container(data, false)
}

fn list_iff_chunks(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    list_chunk_container(data, true)
}

/// Той самий прохід боксами, що й `validate_isobmff`, але збирає тип і повний
/// розмір кожного боксу (`ftyp`, `moov`, `mdat`...) замість лише межі файлу.
fn list_isobmff_boxes(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let mut pos = 0;
    let mut entries = Vec::new();

    while let Some(header) = data.get(pos..pos + 8) {
        let box_size = u32::from_be_bytes(header[0..4].try_into().ok()?) as u64;
        let name = String::from_utf8_lossy(&header[4..8]).into_owned();

        if box_size == 0 {
            entries.push(ArchiveEntry { name, size: (data.len() - pos) as u64 });
            break;
        }
        let total_len = if box_size == 1 {
            u64::from_be_bytes(data.get(pos + 8..pos + 16)?.try_into().ok()?)
        } else {
            box_size
        };
        if total_len < 8 {
            break;
        }

        entries.push(ArchiveEntry { name, size: total_len });

        let box_end = pos as u64 + total_len;
        if box_end > data.len() as u64 {
            break;
        }
        pos = box_end as usize;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Секції ELF через уже готовий парсер `goblin` — ім'я береться з таблиці
/// рядків секцій (`shdr_strtab`), безіменні (нульові) секції пропускаються.
fn list_elf_sections(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    let mut entries = Vec::new();
    for section in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else { continue };
        if name.is_empty() {
            continue;
        }
        entries.push(ArchiveEntry { name: name.to_string(), size: section.sh_size });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Секції PE через уже готовий парсер `goblin`.
fn list_pe_sections(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let mut entries = Vec::new();
    for section in &pe.sections {
        let name = section.name().unwrap_or("").trim_end_matches('\0').to_string();
        entries.push(ArchiveEntry { name, size: section.size_of_raw_data as u64 });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Секції Mach-O: та сама навігація по load commands, що й у
/// `validate_macho_generic` (крок — завжди `cmdsize`), але замість лише
/// максимуму `fileoff+filesize` серед сегментів (`LC_SEGMENT`/`LC_SEGMENT_64`)
/// заходить усередину кожного сегмента й перелічує його секції
/// (`segname,sectname` — конвенція `otool -l`) з їхнім розміром.
fn list_macho_sections(data: &[u8], is64: bool, is_be: bool) -> Option<Vec<ArchiveEntry>> {
    const LC_SEGMENT: u32 = 0x1;
    const LC_SEGMENT_64: u32 = 0x19;

    let read_u32 = |pos: usize| -> Option<u32> {
        let arr: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
        Some(if is_be { u32::from_be_bytes(arr) } else { u32::from_le_bytes(arr) })
    };
    let read_u64 = |pos: usize| -> Option<u64> {
        let arr: [u8; 8] = data.get(pos..pos + 8)?.try_into().ok()?;
        Some(if is_be { u64::from_be_bytes(arr) } else { u64::from_le_bytes(arr) })
    };

    let header_len: usize = if is64 { 32 } else { 28 };
    let ncmds = read_u32(16)? as usize;

    let mut entries = Vec::new();
    let mut pos = header_len;

    for _ in 0..ncmds {
        let cmd = read_u32(pos)?;
        let cmdsize = read_u32(pos + 4)? as usize;
        if cmdsize < 8 {
            return None;
        }

        let is_segment = (cmd == LC_SEGMENT && !is64) || (cmd == LC_SEGMENT_64 && is64);
        if is_segment {
            let (nsects_offset, sections_start, section_len) = if is64 { (64, 72, 80) } else { (48, 56, 68) };
            let segname = bytes_to_trimmed_string(data.get(pos + 8..pos + 24)?).unwrap_or_default();
            let nsects = read_u32(pos + nsects_offset)? as usize;

            for i in 0..nsects {
                let section_start = pos + sections_start + i * section_len;
                let section = data.get(section_start..section_start + section_len)?;
                let sectname = bytes_to_trimmed_string(&section[0..16]).unwrap_or_default();
                let size = if is64 { read_u64(section_start + 40)? } else { read_u32(section_start + 36)? as u64 };
                entries.push(ArchiveEntry { name: format!("{segname},{sectname}"), size });
            }
        }

        pos += cmdsize;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Архітектури Mach-O Fat/Universal Binary: та сама структура запису, що й у
/// `validate_macho_fat`, але замість максимуму — перелік усіх архітектур
/// (людинозрозуміла назва cputype) з розміром вбудованого бінарника.
fn list_macho_fat_archs(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    if data.get(0..4)? != b"\xca\xfe\xba\xbe" {
        return None;
    }
    let nfat_arch = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    if nfat_arch == 0 || nfat_arch > 100 {
        return None;
    }

    let arches = data.get(8..8 + nfat_arch * 20)?;
    let mut entries = Vec::with_capacity(nfat_arch);
    for arch in arches.chunks_exact(20) {
        let cputype = i32::from_be_bytes(arch[0..4].try_into().ok()?);
        let size = u32::from_be_bytes(arch[12..16].try_into().ok()?) as u64;
        entries.push(ArchiveEntry { name: macho_cputype_name(cputype).to_string(), size });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Людинозрозумілі назви найпоширеніших значень `cputype` Mach-O (визначені
/// в `<mach/machine.h>`); менш поширені архітектури показуються як число.
fn macho_cputype_name(cputype: i32) -> String {
    match cputype {
        0x00000007 => "x86".to_string(),
        0x01000007 => "x86_64".to_string(),
        0x0000000c => "arm".to_string(),
        0x0100000c => "arm64".to_string(),
        0x00000012 => "ppc".to_string(),
        0x01000012 => "ppc64".to_string(),
        other => format!("cputype 0x{other:x}"),
    }
}

/// Читає SQLite varint (1-9 байт: 7 корисних біт на байт зі старшим
/// continuation-бітом, крім останнього/9-го байта, де корисні всі 8 біт).
/// Повертає (значення, кількість спожитих байтів).
fn read_sqlite_varint(data: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    for i in 0..8 {
        let byte = *data.get(i)?;
        result = (result << 7) | (byte & 0x7f) as i64;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    result = (result << 8) | *data.get(8)? as i64;
    Some((result, 9))
}

/// Довжина значення (у байтах) для serial type запису SQLite (формат
/// "record": https://www.sqlite.org/fileformat2.html#record_format).
fn sqlite_serial_type_len(serial_type: i64) -> usize {
    match serial_type {
        0 | 8 | 9 | 10 | 11 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        n if n >= 12 && n % 2 == 0 => ((n - 12) / 2) as usize, // BLOB
        n if n >= 13 => ((n - 13) / 2) as usize,                // TEXT (n тут завжди непарне)
        _ => 0,
    }
}

/// Розбирає один запис SQLite (varint header_length + varint-список serial
/// types + самі значення) — повертає зрізи байтів кожної колонки в порядку
/// їх оголошення в таблиці.
fn read_sqlite_record(payload: &[u8]) -> Option<Vec<&[u8]>> {
    let (header_len, header_len_size) = read_sqlite_varint(payload)?;
    let header_len = header_len as usize;

    let mut pos = header_len_size;
    let mut serial_types = Vec::new();
    while pos < header_len {
        let (serial_type, n) = read_sqlite_varint(payload.get(pos..)?)?;
        serial_types.push(serial_type);
        pos += n;
    }

    let mut body_pos = header_len;
    let mut columns = Vec::with_capacity(serial_types.len());
    for st in serial_types {
        let len = sqlite_serial_type_len(st);
        columns.push(payload.get(body_pos..body_pos + len)?);
        body_pos += len;
    }
    Some(columns)
}

/// Схема бази SQLite: сторінка 1 (перша, що включає 100-байтовий заголовок
/// файлу як свої перші байти) містить кореневу B-tree сторінку таблиці
/// `sqlite_schema` — по одному запису на таблицю/індекс/в'ю/тригер, з
/// колонками `type`, `name`, `tbl_name`, `rootpage`, `sql`. Підтримується
/// лише коренева сторінка типу "leaf table" (0x0d) — це переважна більшість
/// реальних баз; "interior"-сторінки (0x05, трапляються лише при величезній
/// кількості об'єктів схеми) не підтримуються.
fn list_sqlite_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let page_size_raw = u16::from_be_bytes(data.get(16..18)?.try_into().ok()?);
    let page_size: usize = match page_size_raw {
        1 => 65536,
        n if n.is_power_of_two() && (512..=32768).contains(&n) => n as usize,
        _ => return None,
    };
    let page1 = data.get(0..page_size)?;

    let page_header = page1.get(100..108)?;
    if page_header[0] != 0x0d {
        return None;
    }
    let num_cells = u16::from_be_bytes(page_header[3..5].try_into().ok()?) as usize;

    const CELL_PTR_START: usize = 108; // 100 (заголовок файлу) + 8 (заголовок leaf-сторінки)
    let mut entries = Vec::with_capacity(num_cells);
    for i in 0..num_cells {
        let ptr_pos = CELL_PTR_START + i * 2;
        let cell_offset = u16::from_be_bytes(page1.get(ptr_pos..ptr_pos + 2)?.try_into().ok()?) as usize;
        let cell = page1.get(cell_offset..)?;

        let (payload_len, n1) = read_sqlite_varint(cell)?;
        let (_rowid, n2) = read_sqlite_varint(cell.get(n1..)?)?;
        // SQLite varint кодує довільне 64-бітне ціле зі знаком — крафтований
        // 9-байтовий varint може дати від'ємне `payload_len`; без `try_from`
        // (що відкидає від'ємні значення) наступний каст `as usize` дав би
        // величезне число, а `n1 + n2 + ...` без `checked_add` панікував би
        // при переповненні (debug-збірка) замість безпечного `None`.
        let payload_len = usize::try_from(payload_len).ok()?;
        let payload_start = n1.checked_add(n2)?;
        let payload = cell.get(payload_start..payload_start.checked_add(payload_len)?)?;

        let columns = read_sqlite_record(payload)?;
        let obj_type = columns.first().map(|c| String::from_utf8_lossy(c).into_owned()).unwrap_or_default();
        let name = columns.get(1).map(|c| String::from_utf8_lossy(c).into_owned()).unwrap_or_default();
        let sql_len = columns.get(4).map_or(0, |c| c.len() as u64);

        entries.push(ArchiveEntry { name: format!("{obj_type}: {name}"), size: sql_len });
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// ISO 9660: Primary Volume Descriptor (сектор 16, 2048 байт) містить
/// вбудований directory record кореневого каталогу за офсетом 156 —
/// `extent_location`/`data_length` вказують, де в образі лежать дані самого
/// кореневого каталогу. Перелічує лише верхній рівень (без рекурсії у
/// підкаталоги) — записи `\x00`/`\x01` ("." і "..") пропускаються, а
/// традиційний суфікс версії файлу (`;1`) прибирається для читабельності.
fn list_iso9660_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const SECTOR: usize = 2048;

    let pvd = data.get(16 * SECTOR..16 * SECTOR + SECTOR)?;
    if pvd.get(0..6)? != b"\x01CD001" {
        return None;
    }
    let root_record = pvd.get(156..156 + 34)?;
    let extent = u32::from_le_bytes(root_record.get(2..6)?.try_into().ok()?) as usize;
    let dir_len = u32::from_le_bytes(root_record.get(10..14)?.try_into().ok()?) as usize;

    let dir_data = data.get(extent * SECTOR..extent.checked_mul(SECTOR)?.checked_add(dir_len)?)?;
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < dir_data.len() {
        let record_len = dir_data[pos] as usize;
        if record_len == 0 {
            // Директорійні записи не перетинають межу сектора — переходимо до наступного.
            pos = (pos / SECTOR + 1) * SECTOR;
            continue;
        }
        let record = dir_data.get(pos..pos + record_len)?;
        let data_length = u32::from_le_bytes(record.get(10..14)?.try_into().ok()?) as u64;
        let id_len = *record.get(32)? as usize;
        let id_bytes = record.get(33..33 + id_len)?;

        if id_bytes != [0u8] && id_bytes != [1u8] {
            let mut name = String::from_utf8_lossy(id_bytes).into_owned();
            if let Some(idx) = name.rfind(';') {
                name.truncate(idx);
            }
            entries.push(ArchiveEntry { name, size: data_length });
        }
        pos += record_len;
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Читає C-рядок (до NUL) з `data`, посуваючи `pos` за NUL-термінатор.
fn read_cstr<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let start = *pos;
    let nul = memchr::memchr(0, data.get(start..)?)?;
    *pos = start + nul + 1;
    std::str::from_utf8(data.get(start..start + nul)?).ok()
}

/// VPK (Source engine): "дерево каталогу" — потрійно вкладений список
/// NUL-термінованих рядків (розширення → шлях → ім'я файлу), кожен
/// завершується порожнім рядком; після імені йде фіксований 18-байтовий
/// запис (CRC+PreloadBytes+ArchiveIndex+EntryOffset+EntryLength+Terminator).
/// Розмір знахідки — EntryLength+PreloadBytes (частина даних може бути
/// "preload"-байтами, вбудованими прямо в дерево каталогу).
fn list_vpk_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    let version = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
    let tree_size = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?) as usize;
    let tree_start: usize = match version {
        1 => 12,
        2 => 28,
        _ => return None,
    };
    let tree = data.get(tree_start..tree_start.checked_add(tree_size)?)?;

    let mut entries = Vec::new();
    let mut pos = 0;
    'extensions: loop {
        let ext = read_cstr(tree, &mut pos)?;
        if ext.is_empty() {
            break 'extensions;
        }
        loop {
            let path = read_cstr(tree, &mut pos)?;
            if path.is_empty() {
                break;
            }
            loop {
                let name = read_cstr(tree, &mut pos)?;
                if name.is_empty() {
                    break;
                }
                let entry = tree.get(pos..pos + 18)?;
                pos += 18;
                let preload_bytes = u16::from_le_bytes(entry[4..6].try_into().ok()?) as u64;
                let entry_length = u32::from_le_bytes(entry[12..16].try_into().ok()?) as u64;

                let full_name =
                    if path.is_empty() || path == " " { format!("{name}.{ext}") } else { format!("{path}/{name}.{ext}") };
                entries.push(ArchiveEntry { name: full_name, size: entry_length + preload_bytes });
            }
        }
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// RAR (1.5-4.x): той самий прохід блоками, що й `validate_rar`, але для
/// блоків `FILE_HEAD` (0x74) додатково розбирає їхні власні поля —
/// `UNP_SIZE`(4)@4, `NAME_SIZE`(2)@19, ім'я файлу за офсетом 25 (або 33,
/// якщо встановлено прапорець `LHD_LARGE`/0x0100 — тоді перед іменем ще два
/// 4-байтові поля `HIGH_PACK_SIZE`/`HIGH_UNP_SIZE`), усі зсуви — відносно
/// кінця спільного 7-байтового заголовка блоку. Юнікодні імена (прапорець
/// `LHD_UNICODE`) не декодуються за власною RAR-схемою — береться лише
/// ASCII-частина до першого NUL, як "найкраще можливе" наближення.
fn list_rar_entries(data: &[u8]) -> Option<Vec<ArchiveEntry>> {
    const MARKER_LEN: usize = 7;
    const FILE_HEAD: u8 = 0x74;
    const ENDARC_HEAD: u8 = 0x7b;
    const LONG_BLOCK: u16 = 0x8000;
    const LHD_LARGE: u16 = 0x0100;

    let mut pos = MARKER_LEN;
    let mut entries = Vec::new();

    while let Some(header) = data.get(pos..pos + 7) {
        let head_type = header[2];
        let head_flags = u16::from_le_bytes(header[3..5].try_into().ok()?);
        let head_size = u16::from_le_bytes(header[5..7].try_into().ok()?) as usize;
        if head_size < 7 {
            break;
        }

        let add_size = if head_flags & LONG_BLOCK != 0 {
            match data.get(pos + 7..pos + 11) {
                Some(b) => u32::from_le_bytes(b.try_into().ok()?) as usize,
                None => break,
            }
        } else {
            0
        };

        if head_type == FILE_HEAD
            && let Some(file_specific) = data.get(pos + 7..pos + head_size)
        {
            let unp_size = u32::from_le_bytes(file_specific.get(4..8)?.try_into().ok()?) as u64;
            let name_size = u16::from_le_bytes(file_specific.get(19..21)?.try_into().ok()?) as usize;
            let name_offset = if head_flags & LHD_LARGE != 0 { 33 } else { 25 };
            if let Some(name_bytes) = file_specific.get(name_offset..name_offset + name_size) {
                let name = String::from_utf8_lossy(name_bytes).split('\0').next().unwrap_or_default().to_string();
                entries.push(ArchiveEntry { name, size: unp_size });
            }
        }

        let block_end = pos + head_size + add_size;
        if block_end > data.len() {
            break;
        }
        pos = block_end;

        if head_type == ENDARC_HEAD {
            break;
        }
    }

    if entries.is_empty() { None } else { Some(entries) }
}

/// Кілька ключових фактів із заголовка знахідки (тривалість, частота
/// дискретизації, роздільність, мапер ROM тощо) для панелі "Про формат" —
/// там, де повний перегляд (зображення/перелік/текст) недоцільний чи
/// неможливий (немає декодера чи придатної структури для листингу), але сам
/// заголовок уже містить дані, які інакше довелося б вичитувати з hex вручну.
/// `fragment` — той самий вирізаний діапазон знахідки, що й в інших
/// переглядах (офсет 0 відповідає початку знахідки).
pub fn format_facts(format: &str, fragment: &[u8]) -> Option<String> {
    match format {
        "WAV" => wav_facts(fragment),
        "AIFF" | "AIFC" => aiff_facts(fragment),
        "AU" => au_facts(fragment),
        "CAF" => caf_facts(fragment),
        "FLAC" => flac_facts(fragment),
        "DDS" => dds_facts(fragment),
        "KTX" => ktx_facts(fragment),
        "KTX2" => ktx2_facts(fragment),
        "HDR" => hdr_facts(fragment),
        "PVR" => pvr_facts(fragment),
        "NES" => nes_facts(fragment),
        "Genesis" => genesis_facts(fragment),
        "glTF-Binary" => gltf_facts(fragment),
        "PLY" => ply_facts(fragment),
        _ => None,
    }
}

/// `M:SS`, округлено до секунди; `н/д`, якщо тривалість не обчислити
/// (нульова/невідома частота дискретизації тощо).
fn format_duration(total_secs: f64) -> String {
    if !total_secs.is_finite() || total_secs < 0.0 {
        return "н/д".to_string();
    }
    let total = total_secs.round() as u64;
    format!("{}:{:02}", total / 60, total % 60)
}

/// Шукає підчанк за 4-байтовим ID усередині RIFF-контейнера (той самий
/// прохід, що й `list_chunk_container`, але повертає дані ОДНОГО потрібного
/// чанку, а не перелік усіх).
fn find_riff_chunk<'a>(data: &'a [u8], want_id: &[u8; 4]) -> Option<&'a [u8]> {
    let total_size = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let container_end = (8usize.checked_add(total_size)?).min(data.len());

    let mut pos: usize = 12;
    while pos.checked_add(8)? <= container_end {
        let chunk_id = data.get(pos..pos + 4)?;
        let chunk_size = u32::from_le_bytes(data.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
        if chunk_id == want_id {
            return data.get(pos + 8..pos + 8 + chunk_size);
        }
        let padded = chunk_size + chunk_size % 2;
        pos = pos.checked_add(8)?.checked_add(padded)?;
    }
    None
}

/// Той самий пошук, що й `find_riff_chunk`, але для Amiga IFF (big-endian).
fn find_iff_chunk<'a>(data: &'a [u8], want_id: &[u8; 4]) -> Option<&'a [u8]> {
    let total_size = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let container_end = (8usize.checked_add(total_size)?).min(data.len());

    let mut pos: usize = 12;
    while pos.checked_add(8)? <= container_end {
        let chunk_id = data.get(pos..pos + 4)?;
        let chunk_size = u32::from_be_bytes(data.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
        if chunk_id == want_id {
            return data.get(pos + 8..pos + 8 + chunk_size);
        }
        let padded = chunk_size + chunk_size % 2;
        pos = pos.checked_add(8)?.checked_add(padded)?;
    }
    None
}

fn wav_facts(data: &[u8]) -> Option<String> {
    let fmt = find_riff_chunk(data, b"fmt ")?;
    let channels = u16::from_le_bytes(fmt.get(2..4)?.try_into().ok()?);
    let sample_rate = u32::from_le_bytes(fmt.get(4..8)?.try_into().ok()?);
    let byte_rate = u32::from_le_bytes(fmt.get(8..12)?.try_into().ok()?);
    let bits_per_sample = u16::from_le_bytes(fmt.get(14..16)?.try_into().ok()?);

    let mut lines = vec![
        format!("Канали: {channels}"),
        format!("Частота дискретизації: {sample_rate} Гц"),
        format!("Розрядність: {bits_per_sample} біт"),
    ];
    if byte_rate > 0
        && let Some(data_chunk) = find_riff_chunk(data, b"data")
    {
        lines.push(format!("Тривалість: {}", format_duration(data_chunk.len() as f64 / byte_rate as f64)));
    }
    Some(lines.join("\n"))
}

/// Розбирає 80-бітний розширений формат IEEE 754 (використовується у полі
/// `sampleRate` заголовка AIFF `COMM` — рудимент епохи Motorola 68881/x87).
fn parse_ieee80_extended(bytes: &[u8]) -> Option<f64> {
    let sign = if bytes.first()? & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = (((*bytes.first()? as i32 & 0x7f) << 8) | *bytes.get(1)? as i32) - 16383;
    let mantissa = u64::from_be_bytes(bytes.get(2..10)?.try_into().ok()?);
    if exponent == -16383 && mantissa == 0 {
        return Some(0.0);
    }
    Some(sign * mantissa as f64 * 2f64.powi(exponent - 63))
}

fn aiff_facts(data: &[u8]) -> Option<String> {
    let comm = find_iff_chunk(data, b"COMM")?;
    let channels = u16::from_be_bytes(comm.get(0..2)?.try_into().ok()?);
    let num_frames = u32::from_be_bytes(comm.get(2..6)?.try_into().ok()?);
    let sample_size = u16::from_be_bytes(comm.get(6..8)?.try_into().ok()?);
    let sample_rate = parse_ieee80_extended(comm.get(8..18)?)?;

    let mut lines = vec![
        format!("Канали: {channels}"),
        format!("Частота дискретизації: {} Гц", sample_rate.round() as i64),
        format!("Розрядність: {sample_size} біт"),
    ];
    if sample_rate > 0.0 {
        lines.push(format!("Тривалість: {}", format_duration(num_frames as f64 / sample_rate)));
    }
    Some(lines.join("\n"))
}

/// Кількість біт на семпл для значень поля `encoding` заголовка AU
/// (Sun/NeXT); `None` для стиснених/нестандартних кодувань, для яких
/// тривалість неможливо порахувати напряму з розміру даних.
fn au_encoding_bits(encoding: u32) -> Option<u32> {
    match encoding {
        1 | 2 => Some(8),   // 8-bit mu-law / 8-bit linear PCM
        3 => Some(16),      // 16-bit linear PCM
        4 => Some(24),      // 24-bit linear PCM
        5 => Some(32),      // 32-bit linear PCM
        6 => Some(32),      // 32-bit float
        7 => Some(64),      // 64-bit float
        _ => None,
    }
}

fn au_facts(data: &[u8]) -> Option<String> {
    let data_size = u32::from_be_bytes(data.get(8..12)?.try_into().ok()?);
    let encoding = u32::from_be_bytes(data.get(12..16)?.try_into().ok()?);
    let sample_rate = u32::from_be_bytes(data.get(16..20)?.try_into().ok()?);
    let channels = u32::from_be_bytes(data.get(20..24)?.try_into().ok()?);

    let mut lines = vec![format!("Канали: {channels}"), format!("Частота дискретизації: {sample_rate} Гц")];
    if let Some(bits) = au_encoding_bits(encoding) {
        lines.push(format!("Розрядність: {bits} біт"));
        let bytes_per_frame = (bits / 8).max(1) as u64 * channels.max(1) as u64;
        // `channels`/`sample_rate` — сирі 32-бітні поля з заголовка без
        // верхньої межі; на екстремальних (крафтованих) значеннях добуток
        // може переповнити `u64` (паніка в debug-збірці) — `checked_mul`
        // замість цього просто пропускає рядок тривалості.
        if sample_rate > 0
            && data_size != 0xFFFFFFFF
            && let Some(bytes_per_second) = bytes_per_frame.checked_mul(sample_rate as u64).filter(|&v| v > 0)
        {
            let duration = data_size as f64 / bytes_per_second as f64;
            lines.push(format!("Тривалість: {}", format_duration(duration)));
        }
    }
    Some(lines.join("\n"))
}

/// CAF (Apple Core Audio Format): проходить чанки, доки не знайде `desc`
/// (`AudioStreamBasicDescription` — 36 байт: sampleRate(f64)+formatID(4)+
/// formatFlags(4)+bytesPerPacket(4)+framesPerPacket(4)+bytesPerFrame(4)+
/// channelsPerFrame(4)+bitsPerChannel(4)), завжди перший чанк у файлі.
fn caf_facts(data: &[u8]) -> Option<String> {
    let mut pos: usize = 8; // "caff" + version(2) + flags(2)
    while pos.checked_add(12)? <= data.len() {
        let chunk_type = data.get(pos..pos + 4)?;
        let chunk_size = i64::from_be_bytes(data.get(pos + 4..pos + 12)?.try_into().ok()?);
        let chunk_data_start = pos + 12;

        if chunk_type == b"desc" {
            let desc = data.get(chunk_data_start..chunk_data_start + 36)?;
            let sample_rate = f64::from_be_bytes(desc[0..8].try_into().ok()?);
            let channels = u32::from_be_bytes(desc[28..32].try_into().ok()?);
            let bits = u32::from_be_bytes(desc[32..36].try_into().ok()?);

            let mut lines =
                vec![format!("Канали: {channels}"), format!("Частота дискретизації: {} Гц", sample_rate.round() as i64)];
            if bits > 0 {
                lines.push(format!("Розрядність: {bits} біт"));
            }
            return Some(lines.join("\n"));
        }

        if chunk_size < 0 {
            break; // -1 = "дані до кінця файлу" (рідкісний випадок, не обробляємо)
        }
        pos = chunk_data_start.checked_add(chunk_size as usize)?;
    }
    None
}

/// FLAC: перший метаданий-блок після `fLaC` завжди `STREAMINFO` (тип 0,
/// 34 байти) — містить упаковане 64-бітне поле sampleRate(20 біт)+
/// channels-1(3 біти)+bitsPerSample-1(5 біт)+totalSamples(36 біт), одразу за
/// minBlockSize/maxBlockSize/minFrameSize/maxFrameSize (10 байт).
fn flac_facts(data: &[u8]) -> Option<String> {
    let block_header = data.get(4..8)?;
    let block_type = block_header[0] & 0x7f;
    let block_len = u32::from_be_bytes([0, block_header[1], block_header[2], block_header[3]]) as usize;
    if block_type != 0 || block_len < 34 {
        return None;
    }

    let info = data.get(8..8 + 34)?;
    let combined = u64::from_be_bytes(info[10..18].try_into().ok()?);
    let sample_rate = (combined >> 44) as u32;
    let channels = ((combined >> 41) & 0x7) as u32 + 1;
    let bits_per_sample = ((combined >> 36) & 0x1f) as u32 + 1;
    let total_samples = combined & 0xF_FFFF_FFFF;

    let mut lines = vec![
        format!("Канали: {channels}"),
        format!("Частота дискретизації: {sample_rate} Гц"),
        format!("Розрядність: {bits_per_sample} біт"),
    ];
    if sample_rate > 0 && total_samples > 0 {
        lines.push(format!("Тривалість: {}", format_duration(total_samples as f64 / sample_rate as f64)));
    }
    Some(lines.join("\n"))
}

fn dds_facts(data: &[u8]) -> Option<String> {
    let height = u32::from_le_bytes(data.get(12..16)?.try_into().ok()?);
    let width = u32::from_le_bytes(data.get(16..20)?.try_into().ok()?);
    Some(format!("Роздільність: {width}×{height}"))
}

fn ktx_facts(data: &[u8]) -> Option<String> {
    let width = u32::from_le_bytes(data.get(36..40)?.try_into().ok()?);
    let height = u32::from_le_bytes(data.get(40..44)?.try_into().ok()?);
    if height == 0 {
        Some(format!("Роздільність: {width} (1D-текстура)"))
    } else {
        Some(format!("Роздільність: {width}×{height}"))
    }
}

fn ktx2_facts(data: &[u8]) -> Option<String> {
    let width = u32::from_le_bytes(data.get(20..24)?.try_into().ok()?);
    let height = u32::from_le_bytes(data.get(24..28)?.try_into().ok()?);
    if height == 0 {
        Some(format!("Роздільність: {width} (1D-текстура)"))
    } else {
        Some(format!("Роздільність: {width}×{height}"))
    }
}

/// Radiance HDR: текстовий заголовок (змінна кількість рядків `ЗМІННА=значення`),
/// за яким іде рядок роздільності на кшталт `-Y 2048 +X 4096`.
fn hdr_facts(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&data[..data.len().min(2048)]);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let [y_sign, y_val, x_sign, x_val] = tokens[..]
            && (y_sign == "-Y" || y_sign == "+Y")
            && (x_sign == "-X" || x_sign == "+X")
        {
            let height: u32 = y_val.parse().ok()?;
            let width: u32 = x_val.parse().ok()?;
            return Some(format!("Роздільність: {width}×{height}"));
        }
    }
    None
}

/// PowerVR-текстура v3: заголовок 52 байти, `height`/`width` — фіксовані
/// 32-бітні поля одразу за `flags`/`pixelFormat`/`colourSpace`/`channelType`.
fn pvr_facts(data: &[u8]) -> Option<String> {
    let height = u32::from_le_bytes(data.get(24..28)?.try_into().ok()?);
    let width = u32::from_le_bytes(data.get(28..32)?.try_into().ok()?);
    Some(format!("Роздільність: {width}×{height}"))
}

/// iNES: 16-байтовий заголовок прямо містить розміри PRG/CHR ROM (в
/// одиницях 16 KiB/8 KiB) і номер мапера, розбитий навпіл між `flags6`
/// (старша половина в молодшому нібблі) і `flags7` (старша половина).
fn nes_facts(data: &[u8]) -> Option<String> {
    let prg_16k = *data.get(4)?;
    let chr_8k = *data.get(5)?;
    let flags6 = *data.get(6)?;
    let flags7 = *data.get(7)?;
    let mapper = (flags7 & 0xF0) | (flags6 >> 4);
    let mirroring = if flags6 & 0x08 != 0 {
        "чотириекранне"
    } else if flags6 & 0x01 != 0 {
        "вертикальне"
    } else {
        "горизонтальне"
    };

    Some(format!(
        "PRG ROM: {} KiB\nCHR ROM: {} KiB\nМапер: {mapper}\nДзеркалення: {mirroring}",
        prg_16k as u32 * 16,
        chr_8k as u32 * 8
    ))
}

/// Sega Genesis/Mega Drive: заголовок за офсетом 0x100 містить назву гри та
/// підтримувані регіони прямим ASCII-текстом — не треба нічого обчислювати,
/// лише зчитати й обрізати пробіли.
fn genesis_facts(data: &[u8]) -> Option<String> {
    let domestic = bytes_to_trimmed_string(data.get(0x120..0x120 + 48)?)?;
    let mut lines = vec![format!("Назва: {domestic}")];
    if let Some(region) = data.get(0x1f0..0x1f0 + 3).and_then(bytes_to_trimmed_string) {
        lines.push(format!("Регіон: {region}"));
    }
    Some(lines.join("\n"))
}

/// glTF Binary (.glb): заголовок(12) + перший чанк завжди `JSON` — повна
/// сцена в текстовому JSON, який уже вміємо парсити (`serde_json`, наявна
/// залежність). Замість повного дампу JSON — кілька підсумкових чисел.
fn gltf_facts(data: &[u8]) -> Option<String> {
    let chunk_length = u32::from_le_bytes(data.get(12..16)?.try_into().ok()?) as usize;
    if data.get(16..20)? != b"JSON" {
        return None;
    }
    let json = serde_json::from_slice::<serde_json::Value>(data.get(20..20 + chunk_length)?).ok()?;

    let array_len = |key: &str| json.get(key).and_then(|v| v.as_array()).map_or(0, Vec::len);
    let mut lines = vec![
        format!("Сцени: {}", array_len("scenes")),
        format!("Вузли: {}", array_len("nodes")),
        format!("Меші: {}", array_len("meshes")),
        format!("Матеріали: {}", array_len("materials")),
    ];
    let animations = array_len("animations");
    if animations > 0 {
        lines.push(format!("Анімації: {animations}"));
    }
    if let Some(generator) = json.get("asset").and_then(|a| a.get("generator")).and_then(|g| g.as_str()) {
        lines.push(format!("Створено: {generator}"));
    }
    Some(lines.join("\n"))
}

/// PLY: заголовок — завжди ASCII-текст (навіть для `binary_*` варіантів
/// формату) до рядка `end_header` — рядки `format ...` і `element ІМ'Я N`
/// дають усе потрібне без розбору самих даних.
fn ply_facts(data: &[u8]) -> Option<String> {
    let header_end = memchr::memmem::find(data, b"end_header")?;
    let header_text = std::str::from_utf8(&data[..header_end]).ok()?;

    let mut lines = Vec::new();
    for line in header_text.lines() {
        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some("format") => {
                if let Some(fmt) = tokens.next() {
                    lines.push(format!("Формат: {fmt}"));
                }
            }
            Some("element") => {
                if let (Some(name), Some(count)) = (tokens.next(), tokens.next()) {
                    lines.push(format!("{name}: {count}"));
                }
            }
            _ => {}
        }
    }

    if lines.is_empty() { None } else { Some(lines.join("\n")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap_with_junk(core: &[u8]) -> (Vec<u8>, usize) {
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(core);
        data.extend_from_slice(b"-JUNK-SUFFIX-TRAILING-DATA");
        (data, start)
    }

    fn build_minimal_zip(name: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let local_header_offset = 0u32;

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (не перевіряється валідатором)
        out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed size
        out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(content);

        let central_dir_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&local_header_offset.to_le_bytes());
        out.extend_from_slice(name);

        let central_dir_size = out.len() as u32 - central_dir_offset;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        out.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // total entries
        out.extend_from_slice(&central_dir_size.to_le_bytes());
        out.extend_from_slice(&central_dir_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len

        out
    }

    #[test]
    fn zip_exact_boundary() {
        let core = build_minimal_zip(b"hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_zip(&data, start).expect("valid zip must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn zip_truncated_returns_none() {
        let core = build_minimal_zip(b"hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core[..core.len() - 5]);
        assert_eq!(validate_zip(&data, start), None);
    }

    fn build_minimal_gzip(payload: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut out = Vec::new();
        out.extend_from_slice(&[0x1f, 0x8b, 0x08]); // magic + deflate method
        out.push(0); // flags: жодних опційних полів
        out.extend_from_slice(&[0u8; 4]); // mtime
        out.push(0); // xfl
        out.push(0xff); // os: unknown

        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        out.extend_from_slice(&compressed);

        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (не перевіряється валідатором)
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // isize
        out
    }

    #[test]
    fn gzip_exact_boundary() {
        let core = build_minimal_gzip(b"some repeated payload text ".repeat(100).as_slice());
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_gzip(&data, start).expect("valid gzip must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn gzip_truncated_mid_stream_returns_none() {
        let core = build_minimal_gzip(b"some repeated payload text ".repeat(100).as_slice());
        let (data, start) = wrap_with_junk(&core[..core.len() - 20]);
        assert_eq!(validate_gzip(&data, start), None);
    }

    #[test]
    fn extract_tar_name_reads_name_field() {
        let core = build_minimal_tar("hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_tar_name(&data, start), Some("hello.txt".to_string()));
    }

    #[test]
    fn extract_tar_name_combines_prefix_and_name() {
        let mut core = build_minimal_tar("hello.txt", b"hello world");
        // POSIX prefix-поле — офсет 345, довжина 155
        core[345..345 + 8].copy_from_slice(b"some/dir");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_tar_name(&data, start), Some("some/dir/hello.txt".to_string()));
    }

    fn build_minimal_tar(name: &str, content: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 512;
        let mut header = vec![0u8; BLOCK];
        header[0..name.len()].copy_from_slice(name.as_bytes());
        let size_octal = format!("{:011o}\0", content.len());
        header[124..124 + size_octal.len()].copy_from_slice(size_octal.as_bytes());
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b"00");

        let mut out = header;
        out.extend_from_slice(content);
        let padding = (BLOCK - content.len() % BLOCK) % BLOCK;
        out.extend(std::iter::repeat_n(0u8, padding));
        out.extend(std::iter::repeat_n(0u8, 2 * BLOCK)); // термінуючі нульові блоки
        out
    }

    #[test]
    fn tar_exact_boundary_with_terminator() {
        let core = build_minimal_tar("hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_tar(&data, start).expect("valid tar must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn tar_without_terminator_falls_back_to_lower_confidence() {
        let core = build_minimal_tar("hello.txt", b"hello world");
        let without_terminator = &core[..core.len() - 1024];
        let (data, start) = wrap_with_junk(without_terminator);
        let expected_last_entry_end = start + without_terminator.len() - 1;

        let (end, confidence) = validate_tar(&data, start).expect("partial tar still yields last entry end");
        assert_eq!(end, expected_last_entry_end);
        assert_eq!(confidence, 70);
    }

    fn build_minimal_elf64(section_header_count: u16) -> Vec<u8> {
        let mut e_ident = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0];
        e_ident.extend(std::iter::repeat_n(0u8, 7));

        let sh_offset: u64 = 64;
        let mut header = e_ident;
        header.extend_from_slice(&2u16.to_le_bytes()); // e_type
        header.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine: x86-64
        header.extend_from_slice(&1u32.to_le_bytes()); // e_version
        header.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        header.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        header.extend_from_slice(&sh_offset.to_le_bytes()); // e_shoff
        header.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        header.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        header.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        header.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        header.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        header.extend_from_slice(&section_header_count.to_le_bytes()); // e_shnum
        header.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(header.len(), 64);

        header.extend(std::iter::repeat_n(0u8, 64 * section_header_count as usize));
        header
    }

    #[test]
    fn elf_exact_boundary() {
        let core = build_minimal_elf64(1);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_elf(&data, start).expect("valid elf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    fn build_minimal_pe32(section_raw_data_len: u32) -> Vec<u8> {
        let mut dos = vec![0u8; 64];
        dos[0..2].copy_from_slice(b"MZ");
        dos[0x3C..0x40].copy_from_slice(&64u32.to_le_bytes());

        let pe_sig = b"PE\x00\x00";
        let mut coff = Vec::new();
        coff.extend_from_slice(&0x14cu16.to_le_bytes()); // Machine: i386
        coff.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        coff.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        coff.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        coff.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        coff.extend_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader
        coff.extend_from_slice(&0x0102u16.to_le_bytes()); // Characteristics

        let mut opt = vec![0u8; 224];
        opt[0..2].copy_from_slice(&0x10bu16.to_le_bytes()); // Magic: PE32
        opt[28..32].copy_from_slice(&0x1000u32.to_le_bytes()); // ImageBase
        opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        opt[60..64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        opt[92..96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        let headers_end = (dos.len() + pe_sig.len() + coff.len() + opt.len() + 40) as u32;
        let mut section = vec![0u8; 40];
        section[0..6].copy_from_slice(b".text\0");
        section[8..12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        section[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        section[16..20].copy_from_slice(&section_raw_data_len.to_le_bytes()); // SizeOfRawData
        section[20..24].copy_from_slice(&headers_end.to_le_bytes()); // PointerToRawData

        let mut out = dos;
        out.extend_from_slice(pe_sig);
        out.extend_from_slice(&coff);
        out.extend_from_slice(&opt);
        out.extend_from_slice(&section);
        out.extend(std::iter::repeat_n(0xCCu8, section_raw_data_len as usize));
        out
    }

    #[test]
    fn pe_exact_boundary() {
        let core = build_minimal_pe32(64);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_pe(&data, start).expect("valid pe must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 75);
    }

    fn build_minimal_png() -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();

        // IHDR: length=13, довільний вміст (CRC не перевіряється валідатором)
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend(std::iter::repeat_n(0u8, 13));
        out.extend_from_slice(&0u32.to_be_bytes()); // crc

        // IEND: length=0
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(b"IEND");
        out.extend_from_slice(&0xae426082u32.to_be_bytes());

        out
    }

    #[test]
    fn png_exact_boundary() {
        let core = build_minimal_png();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_png(&data, start).expect("valid png must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn png_truncated_before_iend_returns_none() {
        let core = build_minimal_png();
        // Без trailing junk: інакше суфікс "добудовує" бракуючі байти CRC,
        // і validate_png (який не перевіряє CRC) помилково прийняв би межу.
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 4]);
        assert_eq!(validate_png(&data, start), None);
    }

    fn build_minimal_jpeg_markers_only() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8]; // SOI
        out.extend_from_slice(&[0xff, 0xe0]); // APP0
        out.extend_from_slice(&4u16.to_be_bytes()); // length: включає себе + 2 байти payload
        out.extend_from_slice(&[0xaa, 0xbb]);
        out.extend_from_slice(&[0xff, 0xd9]); // EOI
        out
    }

    #[test]
    fn jpeg_exact_boundary_markers_only() {
        let core = build_minimal_jpeg_markers_only();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_jpeg(&data, start).expect("valid jpeg must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    fn build_minimal_jpeg_with_scan() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8]; // SOI
        out.extend_from_slice(&[0xff, 0xda]); // SOS
        out.extend_from_slice(&8u16.to_be_bytes()); // length: себе(2) + заголовок(6)
        out.extend(std::iter::repeat_n(0u8, 6)); // заголовок скану
        out.extend_from_slice(&[0x11, 0x22]); // ентропійні дані
        out.extend_from_slice(&[0xff, 0x00]); // byte-stuffing: літеральний 0xFF у даних
        out.extend_from_slice(&[0x33]);
        out.extend_from_slice(&[0xff, 0xd0]); // RST0: маркер відновлення, не завершує скан
        out.extend_from_slice(&[0x44]);
        out.extend_from_slice(&[0xff, 0xd9]); // EOI
        out
    }

    #[test]
    fn jpeg_exact_boundary_with_stuffed_bytes_and_restart_marker() {
        let core = build_minimal_jpeg_with_scan();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_jpeg(&data, start).expect("valid jpeg must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn jpeg_truncated_mid_scan_returns_none() {
        let core = build_minimal_jpeg_with_scan();
        let truncated = &core[..core.len() - 3]; // без EOI і останнього байта скану
        let (data, start) = wrap_with_junk(truncated);
        assert_eq!(validate_jpeg(&data, start), None);
    }

    fn build_minimal_sqlite(page_size: u16, page_count: u32, change_counter: u32, version_valid_for: u32) -> Vec<u8> {
        let total_size = page_size as usize * page_count as usize;
        let mut out = vec![0u8; total_size];
        out[0..16].copy_from_slice(b"SQLite format 3\0");
        out[16..18].copy_from_slice(&page_size.to_be_bytes());
        out[24..28].copy_from_slice(&change_counter.to_be_bytes());
        out[28..32].copy_from_slice(&page_count.to_be_bytes());
        out[92..96].copy_from_slice(&version_valid_for.to_be_bytes());
        out
    }

    #[test]
    fn sqlite_exact_boundary_with_synced_counters() {
        let core = build_minimal_sqlite(512, 4, 7, 7);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_sqlite(&data, start).expect("valid sqlite must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn sqlite_lower_confidence_when_counters_mismatch() {
        let core = build_minimal_sqlite(512, 4, 7, 3);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_sqlite(&data, start).expect("valid sqlite must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 60);
    }

    #[test]
    fn sqlite_zero_page_count_returns_none() {
        let mut core = build_minimal_sqlite(512, 1, 1, 1);
        core[28..32].copy_from_slice(&0u32.to_be_bytes()); // "in-header database size" невалідний
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_sqlite(&data, start), None);
    }

    #[test]
    fn sqlite_truncated_returns_none() {
        let core = build_minimal_sqlite(512, 4, 7, 7);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_sqlite(&data, start), None);
    }

    fn rar_block(head_type: u8, flags: u16, extra_header_bytes: &[u8], appended_data: &[u8]) -> Vec<u8> {
        // HEAD_SIZE охоплює весь заголовок, включно з полем ADD_SIZE (як і в
        // реальному форматі — для FILE_HEAD це той самий фізичний простір, що
        // й PACK_SIZE, перше type-специфічне поле).
        let add_size_field_len = if flags & 0x8000 != 0 { 4 } else { 0 };
        let head_size = 7 + add_size_field_len + extra_header_bytes.len();

        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes()); // head_crc (не перевіряється)
        out.push(head_type);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(head_size as u16).to_le_bytes());
        if flags & 0x8000 != 0 {
            out.extend_from_slice(&(appended_data.len() as u32).to_le_bytes());
        }
        out.extend_from_slice(extra_header_bytes);
        out.extend_from_slice(appended_data);
        out
    }

    fn build_minimal_rar_with_endarc() -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x00".to_vec(); // marker block
        out.extend_from_slice(&rar_block(0x73, 0, &[0u8; 6], &[])); // MAIN_HEAD
        out.extend_from_slice(&rar_block(0x74, 0x8000, &[0u8; 25], &[0xAB; 100])); // FILE_HEAD, LONG_BLOCK
        out.extend_from_slice(&rar_block(0x7b, 0, &[], &[])); // ENDARC_HEAD
        out
    }

    #[test]
    fn rar_exact_boundary_with_endarc_and_long_block() {
        let core = build_minimal_rar_with_endarc();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_rar(&data, start).expect("valid rar must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn rar_without_endarc_falls_back_to_lower_confidence() {
        let mut core = b"Rar!\x1a\x07\x00".to_vec();
        core.extend_from_slice(&rar_block(0x73, 0, &[0u8; 6], &[]));
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_rar(&data, start).expect("partial rar still yields last block end");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 65);
    }

    #[test]
    fn rar_only_marker_returns_none() {
        let core = b"Rar!\x1a\x07\x00".to_vec();
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_rar(&data, start), None);
    }

    #[test]
    fn rar_truncated_long_block_returns_none() {
        let core = build_minimal_rar_with_endarc();
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 50]); // обрізаємо посеред FILE_HEAD-даних
        assert_eq!(validate_rar(&data, start), Some((start + 7 + 13 - 1, 65))); // впевненість MAIN_HEAD-фолбеку
    }

    fn build_minimal_7z(packed_data: &[u8], next_header: &[u8]) -> Vec<u8> {
        let mut out = b"7z\xbc\xaf\x27\x1c".to_vec();
        out.extend_from_slice(&[0, 4]); // версія (не перевіряється)
        out.extend_from_slice(&0u32.to_le_bytes()); // StartHeaderCRC (не перевіряється)
        out.extend_from_slice(&(packed_data.len() as u64).to_le_bytes()); // NextHeaderOffset
        out.extend_from_slice(&(next_header.len() as u64).to_le_bytes()); // NextHeaderSize
        out.extend_from_slice(&0u32.to_le_bytes()); // NextHeaderCRC (не перевіряється)
        out.extend_from_slice(packed_data);
        out.extend_from_slice(next_header);
        out
    }

    #[test]
    fn sevenzip_exact_boundary() {
        let core = build_minimal_7z(&[0xCD; 200], &[0xEF; 40]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_7z(&data, start).expect("valid 7z must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn sevenzip_truncated_returns_none() {
        let core = build_minimal_7z(&[0xCD; 200], &[0xEF; 40]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_7z(&data, start), None);
    }

    fn build_minimal_riff(form_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = b"RIFF".to_vec();
        let chunk_size = 4 + payload.len() as u32; // form_type(4) + payload
        out.extend_from_slice(&chunk_size.to_le_bytes());
        out.extend_from_slice(form_type);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn riff_exact_boundary() {
        let core = build_minimal_riff(b"WEBP", &[0xAB; 50]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_riff(&data, start).expect("valid riff must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn riff_truncated_returns_none() {
        let core = build_minimal_riff(b"CDR6", &[0xAB; 50]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_riff(&data, start), None);
    }

    fn build_minimal_ico(img_type: u16, entries_meta: &[(u32, u32)], total_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; 6 + entries_meta.len() * 16];
        out[2..4].copy_from_slice(&img_type.to_le_bytes());
        out[4..6].copy_from_slice(&(entries_meta.len() as u16).to_le_bytes());
        for (i, (bytes_in_res, image_offset)) in entries_meta.iter().enumerate() {
            let base = 6 + i * 16;
            out[base + 8..base + 12].copy_from_slice(&bytes_in_res.to_le_bytes());
            out[base + 12..base + 16].copy_from_slice(&image_offset.to_le_bytes());
        }
        out.resize(total_len, 0xCC);
        // Кожен запис має посилатися на правдоподібний DIB-заголовок
        // (biSize = 40, BITMAPINFOHEADER) — це тепер перевіряє валідатор.
        for (_, image_offset) in entries_meta {
            let offset = *image_offset as usize;
            out[offset..offset + 4].copy_from_slice(&40u32.to_le_bytes());
        }
        out
    }

    #[test]
    fn ico_exact_boundary_single_entry() {
        let core = build_minimal_ico(1, &[(100, 22)], 122);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ico(&data, start).expect("valid ico must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn cur_exact_boundary_multiple_entries() {
        let core = build_minimal_ico(2, &[(50, 38), (80, 88)], 168);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ico(&data, start).expect("valid cur must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn ico_truncated_returns_none() {
        let core = build_minimal_ico(1, &[(100, 22)], 122);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_ico(&data, start), None);
    }

    #[test]
    fn ico_rejects_arithmetically_consistent_but_non_image_payload() {
        // Directory-запис арифметично узгоджений (offset+size у межах
        // файлу), але за image_offset — не PNG і не правдоподібний DIB-
        // заголовок (0xCC-філлер): саме такий "збіг" масово траплявся на
        // щільних бінарних файлах (дампи дисків) до додавання цієї перевірки.
        let mut core = build_minimal_ico(1, &[(100, 22)], 122);
        core[22..26].copy_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_ico(&data, start), None);
    }

    fn build_minimal_icns(payload_len: usize) -> Vec<u8> {
        let total = 8 + payload_len;
        let mut out = b"icns".to_vec();
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend(std::iter::repeat_n(0xABu8, payload_len));
        out
    }

    #[test]
    fn icns_exact_boundary() {
        let core = build_minimal_icns(200);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_icns(&data, start).expect("valid icns must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn icns_truncated_returns_none() {
        let core = build_minimal_icns(200);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_icns(&data, start), None);
    }

    fn build_isobmff_box(box_type: &[u8; 4], payload_len: usize) -> Vec<u8> {
        let size = 8 + payload_len as u32;
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend(std::iter::repeat_n(0u8, payload_len));
        out
    }

    fn build_minimal_heic_boxes() -> Vec<u8> {
        let mut out = build_isobmff_box(b"ftyp", 8);
        out.extend_from_slice(&build_isobmff_box(b"meta", 20));
        out.extend_from_slice(&build_isobmff_box(b"mdat", 100));
        out
    }

    #[test]
    fn isobmff_exact_boundary_at_end_of_data() {
        // Без trailing junk: box-обхід завершується успішно лише тоді, коли
        // впирається точно в кінець наявних даних (`pos == data.len()`).
        let core = build_minimal_heic_boxes();
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_isobmff(&data, start).expect("valid isobmff must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn isobmff_size_zero_extends_to_end_of_data() {
        let mut core = build_isobmff_box(b"ftyp", 8);
        core.extend_from_slice(&0u32.to_be_bytes()); // size == 0: "триває до кінця файлу"
        core.extend_from_slice(b"mdat");
        core.extend(std::iter::repeat_n(0xEEu8, 40));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_isobmff(&data, start).expect("valid isobmff must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn isobmff_truncated_last_box_falls_back_to_lower_confidence() {
        let core = build_minimal_heic_boxes(); // ftyp(16) + meta(28) + mdat(108) = 152
        let truncated = &core[..16 + 28 + 50]; // заголовок mdat є, але з 100 заявлених байт даних лише 50 присутні

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(truncated);
        let expected_last_good_end = start + 16 + 28 - 1;

        let (end, confidence) =
            validate_isobmff(&data, start).expect("partial isobmff still yields last box end");
        assert_eq!(end, expected_last_good_end);
        assert_eq!(confidence, 70);
    }

    #[test]
    fn isobmff_no_valid_box_returns_none() {
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&[0, 0, 0]); // менше 8 байт — навіть заголовок боксу не читається
        assert_eq!(validate_isobmff(&data, start), None);
    }

    fn build_minimal_mng() -> Vec<u8> {
        let mut out = b"\x8aMNG\r\n\x1a\n".to_vec();
        out.extend_from_slice(&0u32.to_be_bytes()); // MHDR length
        out.extend_from_slice(b"MHDR");
        out.extend_from_slice(&0u32.to_be_bytes()); // crc (не перевіряється)
        out.extend_from_slice(&0u32.to_be_bytes()); // MEND length
        out.extend_from_slice(b"MEND");
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    #[test]
    fn mng_exact_boundary() {
        let core = build_minimal_mng();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_mng(&data, start).expect("valid mng must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    fn build_minimal_jng() -> Vec<u8> {
        let mut out = b"\x8bJNG\r\n\x1a\n".to_vec();
        out.extend_from_slice(&0u32.to_be_bytes()); // JHDR length
        out.extend_from_slice(b"JHDR");
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // JEND length
        out.extend_from_slice(b"JEND");
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    #[test]
    fn jng_exact_boundary() {
        let core = build_minimal_jng();
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_jng(&data, start).expect("valid jng must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    fn build_minimal_eps_binary(ps_off: u32, ps_len: u32, wmf_off: u32, wmf_len: u32, tiff_off: u32, tiff_len: u32, total_len: usize) -> Vec<u8> {
        let mut out = b"\xc5\xd0\xd3\xc6".to_vec();
        out.extend_from_slice(&ps_off.to_le_bytes());
        out.extend_from_slice(&ps_len.to_le_bytes());
        out.extend_from_slice(&wmf_off.to_le_bytes());
        out.extend_from_slice(&wmf_len.to_le_bytes());
        out.extend_from_slice(&tiff_off.to_le_bytes());
        out.extend_from_slice(&tiff_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // checksum (не перевіряється)
        out.resize(total_len, 0xCC);
        out
    }

    #[test]
    fn eps_binary_exact_boundary_from_furthest_section() {
        // TIFF-прев'ю (offset 500, довжина 100) закінчується далі, ніж PS-секція
        let core = build_minimal_eps_binary(30, 400, 0, 0, 500, 100, 600);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_eps_binary_header(&data, start).expect("valid eps binary must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn eps_binary_truncated_returns_none() {
        let core = build_minimal_eps_binary(30, 400, 0, 0, 500, 100, 600);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 50]);
        assert_eq!(validate_eps_binary_header(&data, start), None);
    }

    fn build_standard_wmf_header(file_size_words: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_le_bytes()); // fileType: 1 = в пам'яті
        out.extend_from_slice(&9u16.to_le_bytes()); // headerSize: завжди 9 слів
        out.extend_from_slice(&0x0300u16.to_le_bytes()); // version
        out.extend_from_slice(&file_size_words.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // numOfObjects
        out.extend_from_slice(&0u32.to_le_bytes()); // maxRecord
        out.extend_from_slice(&0u16.to_le_bytes()); // numOfParams
        out
    }

    #[test]
    fn wmf_placeable_exact_boundary() {
        let mut core = b"\xd7\xcd\xc6\x9a\x00\x00".to_vec();
        core.extend(std::iter::repeat_n(0u8, 16)); // решта 22-байтового placeable-заголовка
        let payload = vec![0xAB; 40];
        let file_size_words = (build_standard_wmf_header(0).len() + payload.len()) as u32 / 2;
        core.extend_from_slice(&build_standard_wmf_header(file_size_words));
        core.extend_from_slice(&payload);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_wmf(&data, start).expect("valid placeable wmf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn wmf_standard_without_placeable_wrapper_has_lower_confidence() {
        let payload = vec![0xAB; 40];
        let file_size_words = (build_standard_wmf_header(0).len() + payload.len()) as u32 / 2;
        let mut core = build_standard_wmf_header(file_size_words);
        core.extend_from_slice(&payload);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_wmf(&data, start).expect("valid standard wmf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 55);
    }

    #[test]
    fn wmf_truncated_returns_none() {
        let payload = vec![0xAB; 40];
        let file_size_words = (build_standard_wmf_header(0).len() + payload.len()) as u32 / 2;
        let mut core = build_standard_wmf_header(file_size_words);
        core.extend_from_slice(&payload);

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_wmf(&data, start), None);
    }

    fn build_minimal_emf(n_bytes: u32) -> Vec<u8> {
        let mut out = vec![0u8; 52];
        out[0..4].copy_from_slice(&1u32.to_le_bytes()); // iType = EMR_HEADER
        out[40..44].copy_from_slice(b" EMF"); // dSignature
        out[48..52].copy_from_slice(&n_bytes.to_le_bytes());
        out.resize(n_bytes as usize, 0xCC);
        out
    }

    #[test]
    fn emf_exact_boundary() {
        let core = build_minimal_emf(200);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_emf(&data, start).expect("valid emf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn emf_truncated_returns_none() {
        let core = build_minimal_emf(200);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 20]);
        assert_eq!(validate_emf(&data, start), None);
    }

    fn put_u32(out: &mut Vec<u8>, v: u32, is_be: bool) {
        if is_be {
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn put_u64(out: &mut Vec<u8>, v: u64, is_be: bool) {
        if is_be {
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn build_mach_header32(is_be: bool, ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 0xfeedface, is_be); // magic (не перевіряється валідатором)
        put_u32(&mut out, 0, is_be); // cputype
        put_u32(&mut out, 0, is_be); // cpusubtype
        put_u32(&mut out, 2, is_be); // filetype: MH_EXECUTE
        put_u32(&mut out, ncmds, is_be);
        put_u32(&mut out, sizeofcmds, is_be);
        put_u32(&mut out, 0, is_be); // flags
        out
    }

    fn build_mach_header64(is_be: bool, ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut out = build_mach_header32(is_be, ncmds, sizeofcmds);
        put_u32(&mut out, 0, is_be); // reserved
        out
    }

    fn build_lc_segment32(is_be: bool, fileoff: u32, filesize: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 0x1, is_be); // LC_SEGMENT
        put_u32(&mut out, 56, is_be); // cmdsize
        out.extend_from_slice(&[0u8; 16]); // segname
        put_u32(&mut out, 0, is_be); // vmaddr
        put_u32(&mut out, filesize, is_be); // vmsize
        put_u32(&mut out, fileoff, is_be);
        put_u32(&mut out, filesize, is_be);
        put_u32(&mut out, 0, is_be); // maxprot
        put_u32(&mut out, 0, is_be); // initprot
        put_u32(&mut out, 0, is_be); // nsects
        put_u32(&mut out, 0, is_be); // flags
        out
    }

    fn build_lc_segment64(is_be: bool, vmsize: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        // vmsize навмисно приймається окремим параметром (відмінним від
        // fileoff/filesize у тестах) — щоб тест ловив регресію, якби
        // валідатор колись знову переплутав зсуви 8-байтових полів
        // vmaddr/vmsize/fileoff/filesize (на відміну від 32-бітної версії,
        // де всі поля 4-байтові й зсуви інші).
        let mut out = Vec::new();
        put_u32(&mut out, 0x19, is_be); // LC_SEGMENT_64
        put_u32(&mut out, 72, is_be); // cmdsize
        out.extend_from_slice(&[0u8; 16]); // segname
        put_u64(&mut out, 0, is_be); // vmaddr
        put_u64(&mut out, vmsize, is_be);
        put_u64(&mut out, fileoff, is_be);
        put_u64(&mut out, filesize, is_be);
        put_u32(&mut out, 0, is_be); // maxprot
        put_u32(&mut out, 0, is_be); // initprot
        put_u32(&mut out, 0, is_be); // nsects
        put_u32(&mut out, 0, is_be); // flags
        out
    }

    #[test]
    fn macho_64le_exact_boundary_via_segment_with_distinct_vmsize() {
        // Ізольований тест саме на коректність зсувів fileoff/filesize у
        // LC_SEGMENT_64 (без code signature, що міг би замаскувати помилку
        // зсуву через комутативність додавання).
        let lc_seg = build_lc_segment64(false, 999_999, 40, 300); // fileoff=40, filesize=300 → кінець 340
        let header = build_mach_header64(false, 1, lc_seg.len() as u32);

        let mut core = header;
        core.extend_from_slice(&lc_seg);
        core.resize(340, 0xCC);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_macho_64le(&data, start).expect("valid macho64 via segment must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    fn build_lc_symtab(is_be: bool, symoff: u32, nsyms: u32, stroff: u32, strsize: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 0x2, is_be); // LC_SYMTAB
        put_u32(&mut out, 24, is_be); // cmdsize
        put_u32(&mut out, symoff, is_be);
        put_u32(&mut out, nsyms, is_be);
        put_u32(&mut out, stroff, is_be);
        put_u32(&mut out, strsize, is_be);
        out
    }

    fn build_lc_code_signature(is_be: bool, dataoff: u32, datasize: u32) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, 0x1d, is_be); // LC_CODE_SIGNATURE
        put_u32(&mut out, 16, is_be); // cmdsize
        put_u32(&mut out, dataoff, is_be);
        put_u32(&mut out, datasize, is_be);
        out
    }

    #[test]
    fn macho_32be_exact_boundary_via_segment() {
        let header = build_mach_header32(true, 1, 56);
        let lc = build_lc_segment32(true, 28 + 56, 100); // fileoff = header(28)+sizeofcmds(56) = 84
        let mut core = header;
        core.extend_from_slice(&lc);
        core.extend(std::iter::repeat_n(0xABu8, 100));

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_macho_32be(&data, start).expect("valid macho must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    #[test]
    fn macho_64le_exact_boundary_via_code_signature() {
        let lc_seg = build_lc_segment64(false, 999_999, 32, 50); // невеликий сегмент, не найдальший
        let lc_symtab = build_lc_symtab(false, 82, 2, 106, 20); // symtab-кінець 114, strtab-кінець 126
        let lc_sig = build_lc_code_signature(false, 200, 300); // найдальший фрагмент: 200+300=500
        let sizeofcmds = (lc_seg.len() + lc_symtab.len() + lc_sig.len()) as u32;
        let header = build_mach_header64(false, 3, sizeofcmds);

        let mut core = header;
        core.extend_from_slice(&lc_seg);
        core.extend_from_slice(&lc_symtab);
        core.extend_from_slice(&lc_sig);
        core.resize(500, 0xCC);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_macho_64le(&data, start).expect("valid macho64 must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    #[test]
    fn macho_truncated_returns_none() {
        let header = build_mach_header32(true, 1, 56);
        let lc = build_lc_segment32(true, 84, 100);
        let mut core = header;
        core.extend_from_slice(&lc);
        core.extend(std::iter::repeat_n(0xABu8, 100));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_macho_32be(&data, start), None);
    }

    fn build_fat_arch(offset: u32, size: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes()); // cputype
        out.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // align
        out
    }

    fn build_minimal_fat(arches: &[(u32, u32)]) -> Vec<u8> {
        let mut out = b"\xca\xfe\xba\xbe".to_vec();
        out.extend_from_slice(&(arches.len() as u32).to_be_bytes());
        for &(offset, size) in arches {
            out.extend_from_slice(&build_fat_arch(offset, size));
        }
        out
    }

    #[test]
    fn macho_fat_exact_boundary() {
        let mut core = build_minimal_fat(&[(4096, 1000), (8192, 2000)]); // друга архітектура найдальша: 8192+2000=10192
        core.resize(10192, 0xEE);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_macho_fat(&data, start).expect("valid fat macho must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn macho_fat_truncated_returns_none() {
        let mut core = build_minimal_fat(&[(4096, 1000), (8192, 2000)]);
        core.resize(10192, 0xEE);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 50]);
        assert_eq!(validate_macho_fat(&data, start), None);
    }

    fn build_pef_section(container_offset: u32, packed_size: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0i32.to_be_bytes()); // nameOffset
        out.extend_from_slice(&0u32.to_be_bytes()); // defaultAddress
        out.extend_from_slice(&packed_size.to_be_bytes()); // totalSize
        out.extend_from_slice(&packed_size.to_be_bytes()); // unpackedSize
        out.extend_from_slice(&packed_size.to_be_bytes()); // packedSize
        out.extend_from_slice(&container_offset.to_be_bytes()); // containerOffset
        out.push(0); // sectionKind
        out.push(0); // shareKind
        out.push(0); // alignment
        out.push(0); // reservedA
        out
    }

    fn build_minimal_pef(sections: &[(u32, u32)]) -> Vec<u8> {
        let mut out = b"Joy!peff".to_vec();
        out.extend_from_slice(b"pwpc"); // architecture
        out.extend_from_slice(&0u32.to_be_bytes()); // formatVersion
        out.extend_from_slice(&0u32.to_be_bytes()); // dateTimeStamp
        out.extend_from_slice(&0u32.to_be_bytes()); // oldDefVersion
        out.extend_from_slice(&0u32.to_be_bytes()); // oldImpVersion
        out.extend_from_slice(&0u32.to_be_bytes()); // currentVersion
        out.extend_from_slice(&(sections.len() as u16).to_be_bytes()); // sectionCount
        out.extend_from_slice(&0u16.to_be_bytes()); // instSectionCount
        out.extend_from_slice(&0u32.to_be_bytes()); // reservedA
        for &(offset, size) in sections {
            out.extend_from_slice(&build_pef_section(offset, size));
        }
        out
    }

    #[test]
    fn pef_exact_boundary() {
        let mut core = build_minimal_pef(&[(68, 100), (168, 300)]); // друга секція найдальша: 168+300=468
        core.resize(468, 0xDD);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_pef(&data, start).expect("valid pef must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn pef_truncated_returns_none() {
        let mut core = build_minimal_pef(&[(68, 100), (168, 300)]);
        core.resize(468, 0xDD);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 20]);
        assert_eq!(validate_pef(&data, start), None);
    }

    fn build_minimal_iff(form_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = b"FORM".to_vec();
        let chunk_size = 4 + payload.len() as u32;
        out.extend_from_slice(&chunk_size.to_be_bytes());
        out.extend_from_slice(form_type);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn iff_exact_boundary() {
        let core = build_minimal_iff(b"AIFF", &[0xAB; 60]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_iff(&data, start).expect("valid iff must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn iff_truncated_returns_none() {
        let core = build_minimal_iff(b"8SVX", &[0xAB; 60]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_iff(&data, start), None);
    }

    fn build_ogg_page(header_type: u8, segment_table: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = b"OggS".to_vec();
        out.push(0); // version
        out.push(header_type);
        out.extend_from_slice(&0u64.to_le_bytes()); // granule_position
        out.extend_from_slice(&0u32.to_le_bytes()); // serial
        out.extend_from_slice(&0u32.to_le_bytes()); // page_sequence
        out.extend_from_slice(&0u32.to_le_bytes()); // crc
        out.push(segment_table.len() as u8);
        out.extend_from_slice(segment_table);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn ogg_exact_boundary_with_eos() {
        const EOS: u8 = 0x04;
        let core = build_ogg_page(EOS, &[10], &[0xAB; 10]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ogg(&data, start).expect("valid ogg must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn ogg_without_eos_falls_back_to_lower_confidence() {
        let core = build_ogg_page(0x00, &[10], &[0xAB; 10]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ogg(&data, start).expect("partial ogg still yields last page end");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 70);
    }

    #[test]
    fn ogg_no_valid_page_returns_none() {
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(b"NOTOGG");
        assert_eq!(validate_ogg(&data, start), None);
    }

    const ASF_HEADER_GUID: [u8; 16] = [
        0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c,
    ];
    const ASF_FILE_PROPS_GUID: [u8; 16] = [
        0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11, 0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65,
    ];

    fn build_minimal_asf(file_size: u64) -> Vec<u8> {
        let mut file_props_obj = ASF_FILE_PROPS_GUID.to_vec();
        let obj_size: u64 = 24 + 24; // заголовок об'єкта(16+8) + дані (FileID16+FileSize8)
        file_props_obj.extend_from_slice(&obj_size.to_le_bytes());
        file_props_obj.extend_from_slice(&[0u8; 16]); // FileID
        file_props_obj.extend_from_slice(&file_size.to_le_bytes());

        let mut out = ASF_HEADER_GUID.to_vec();
        let header_object_size = 30 + file_props_obj.len() as u64;
        out.extend_from_slice(&header_object_size.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // num_header_objects
        out.push(0);
        out.push(0);
        out.extend_from_slice(&file_props_obj);
        out
    }

    #[test]
    fn asf_exact_boundary() {
        let mut core = build_minimal_asf(500);
        core.resize(500, 0xEE);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_asf(&data, start).expect("valid asf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn asf_truncated_returns_none() {
        let mut core = build_minimal_asf(500);
        core.resize(500, 0xEE);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_asf(&data, start), None);
    }

    fn build_minimal_dsf(file_size: u64) -> Vec<u8> {
        let mut out = b"DSD ".to_vec();
        out.extend_from_slice(&28u64.to_le_bytes()); // chunkSize заголовка (не перевіряється)
        out.extend_from_slice(&file_size.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // metadataOffset
        out
    }

    #[test]
    fn dsf_exact_boundary() {
        let mut core = build_minimal_dsf(300);
        core.resize(300, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_dsf(&data, start).expect("valid dsf must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    #[test]
    fn dsf_truncated_returns_none() {
        let mut core = build_minimal_dsf(300);
        core.resize(300, 0xAB);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_dsf(&data, start), None);
    }

    fn build_caf_chunk(chunk_type: &[u8; 4], size: i64, payload_len: usize) -> Vec<u8> {
        let mut out = chunk_type.to_vec();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend(std::iter::repeat_n(0u8, payload_len));
        out
    }

    #[test]
    fn caf_exact_boundary_at_end_of_data() {
        let mut core = b"caff".to_vec();
        core.extend_from_slice(&1u16.to_be_bytes()); // mFileVersion
        core.extend_from_slice(&0u16.to_be_bytes()); // mFileFlags
        core.extend_from_slice(&build_caf_chunk(b"desc", 32, 32));
        core.extend_from_slice(&build_caf_chunk(b"data", 100, 100));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_caf(&data, start).expect("valid caf must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn caf_unknown_size_extends_to_end_of_data() {
        let mut core = b"caff".to_vec();
        core.extend_from_slice(&1u16.to_be_bytes());
        core.extend_from_slice(&0u16.to_be_bytes());
        core.extend_from_slice(&build_caf_chunk(b"desc", 32, 32));
        core.extend_from_slice(b"data");
        core.extend_from_slice(&(-1i64).to_be_bytes());
        core.extend(std::iter::repeat_n(0xEEu8, 50));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_caf(&data, start).expect("valid caf must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn caf_truncated_falls_back_to_lower_confidence() {
        let mut core = b"caff".to_vec();
        core.extend_from_slice(&1u16.to_be_bytes());
        core.extend_from_slice(&0u16.to_be_bytes());
        core.extend_from_slice(&build_caf_chunk(b"desc", 32, 32));
        let desc_end = core.len();
        core.extend_from_slice(b"data");
        core.extend_from_slice(&200i64.to_be_bytes());
        core.extend(std::iter::repeat_n(0xEEu8, 50)); // заявлено 200 байт даних, присутні лише 50

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);
        let expected_last_good_end = start + desc_end - 1;

        let (end, confidence) = validate_caf(&data, start).expect("partial caf still yields last chunk end");
        assert_eq!(end, expected_last_good_end);
        assert_eq!(confidence, 70);
    }

    fn build_midi_track(events: &[u8]) -> Vec<u8> {
        let mut out = b"MTrk".to_vec();
        out.extend_from_slice(&(events.len() as u32).to_be_bytes());
        out.extend_from_slice(events);
        out
    }

    fn build_minimal_midi(ntracks: u16, tracks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"MThd".to_vec();
        out.extend_from_slice(&6u32.to_be_bytes()); // header_len
        out.extend_from_slice(&1u16.to_be_bytes()); // format
        out.extend_from_slice(&ntracks.to_be_bytes());
        out.extend_from_slice(&96u16.to_be_bytes()); // division
        for t in tracks {
            out.extend_from_slice(t);
        }
        out
    }

    #[test]
    fn midi_exact_boundary() {
        let track1 = build_midi_track(&[0x00, 0x90, 0x40, 0x40]);
        let track2 = build_midi_track(&[0x00, 0xFF, 0x2F, 0x00]);
        let core = build_minimal_midi(2, &[track1, track2]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_midi(&data, start).expect("valid midi must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn midi_truncated_returns_none() {
        let track1 = build_midi_track(&[0x00, 0x90, 0x40, 0x40]);
        let track2 = build_midi_track(&[0x00, 0xFF, 0x2F, 0x00]);
        let core = build_minimal_midi(2, &[track1, track2]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 3]);
        assert_eq!(validate_midi(&data, start), None);
    }

    fn build_minimal_mod(song_length: u8, pattern_order: &[u8], sample_lengths_words: &[u16; 31]) -> Vec<u8> {
        let mut out = vec![0u8; 20]; // title
        for &len_words in sample_lengths_words {
            let mut sample = vec![0u8; 30];
            sample[22..24].copy_from_slice(&len_words.to_be_bytes());
            out.extend_from_slice(&sample);
        }
        out.push(song_length); // offset 950
        out.push(0); // restart position, offset 951
        let mut table = [0u8; 128];
        table[..pattern_order.len()].copy_from_slice(pattern_order);
        out.extend_from_slice(&table); // offset 952..1080
        out.extend_from_slice(b"M.K."); // offset 1080..1084
        out
    }

    #[test]
    fn mod_exact_boundary() {
        let mut sample_lengths = [0u16; 31];
        sample_lengths[0] = 100; // 100 слів = 200 байт
        sample_lengths[1] = 50; // 50 слів = 100 байт
        let pattern_order = [0u8, 1, 0]; // 2 унікальні патерни (0 і 1), song_length=3
        let core_header = build_minimal_mod(3, &pattern_order, &sample_lengths);
        assert_eq!(core_header.len(), 1084);

        let mut core = core_header;
        core.extend(std::iter::repeat_n(0u8, 2 * 1024)); // 2 патерни × 1024 байти
        core.extend(std::iter::repeat_n(0xABu8, 200)); // зразок 1
        core.extend(std::iter::repeat_n(0xCDu8, 100)); // зразок 2

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_mod(&data, start).expect("valid mod must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn mod_truncated_returns_none() {
        let mut sample_lengths = [0u16; 31];
        sample_lengths[0] = 100;
        let pattern_order = [0u8];
        let core_header = build_minimal_mod(1, &pattern_order, &sample_lengths);
        let mut core = core_header;
        core.extend(std::iter::repeat_n(0u8, 1024));
        core.extend(std::iter::repeat_n(0xABu8, 200));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_mod(&data, start), None);
    }

    fn build_cpio_newc_entry(name: &str, content: &[u8]) -> Vec<u8> {
        let namesize = name.len() + 1;
        let field = |v: u32| format!("{v:08x}").into_bytes();
        let mut out = b"070701".to_vec();
        out.extend_from_slice(&field(1)); // ino
        out.extend_from_slice(&field(0o100644)); // mode
        out.extend_from_slice(&field(0)); // uid
        out.extend_from_slice(&field(0)); // gid
        out.extend_from_slice(&field(1)); // nlink
        out.extend_from_slice(&field(0)); // mtime
        out.extend_from_slice(&field(content.len() as u32)); // filesize
        out.extend_from_slice(&field(0)); // devmajor
        out.extend_from_slice(&field(0)); // devminor
        out.extend_from_slice(&field(0)); // rdevmajor
        out.extend_from_slice(&field(0)); // rdevminor
        out.extend_from_slice(&field(namesize as u32)); // namesize
        out.extend_from_slice(&field(0)); // check
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(content);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    #[test]
    fn cpio_newc_exact_boundary() {
        let mut core = build_cpio_newc_entry("hello.txt", b"hello world");
        core.extend_from_slice(&build_cpio_newc_entry("TRAILER!!!", b""));
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_cpio_newc(&data, start).expect("valid cpio newc must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn cpio_newc_truncated_returns_none() {
        let mut core = build_cpio_newc_entry("hello.txt", b"hello world");
        core.extend_from_slice(&build_cpio_newc_entry("TRAILER!!!", b""));
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_cpio_newc(&data, start), None);
    }

    fn build_cpio_odc_entry(name: &str, content: &[u8]) -> Vec<u8> {
        let namesize = name.len() + 1;
        let field6 = |v: u32| format!("{v:06o}").into_bytes();
        let field11 = |v: u64| format!("{v:011o}").into_bytes();
        let mut out = b"070707".to_vec();
        out.extend_from_slice(&field6(0)); // dev
        out.extend_from_slice(&field6(1)); // ino
        out.extend_from_slice(&field6(0o100644)); // mode
        out.extend_from_slice(&field6(0)); // uid
        out.extend_from_slice(&field6(0)); // gid
        out.extend_from_slice(&field6(1)); // nlink
        out.extend_from_slice(&field6(0)); // rdev
        out.extend_from_slice(&field11(0)); // mtime
        out.extend_from_slice(&field6(namesize as u32)); // namesize
        out.extend_from_slice(&field11(content.len() as u64)); // filesize
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn cpio_odc_exact_boundary() {
        let mut core = build_cpio_odc_entry("hello.txt", b"hello world");
        core.extend_from_slice(&build_cpio_odc_entry("TRAILER!!!", b""));
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_cpio_odc(&data, start).expect("valid cpio odc must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn cpio_odc_truncated_returns_none() {
        let mut core = build_cpio_odc_entry("hello.txt", b"hello world");
        core.extend_from_slice(&build_cpio_odc_entry("TRAILER!!!", b""));
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_cpio_odc(&data, start), None);
    }

    fn build_ar_entry(name: &str, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut name_field = name.as_bytes().to_vec();
        name_field.resize(16, b' ');
        out.extend_from_slice(&name_field);
        out.extend_from_slice(format!("{:<12}", 0).as_bytes()); // mtime
        out.extend_from_slice(format!("{:<6}", 0).as_bytes()); // uid
        out.extend_from_slice(format!("{:<6}", 0).as_bytes()); // gid
        out.extend_from_slice(format!("{:<8}", "100644").as_bytes()); // mode
        out.extend_from_slice(format!("{:<10}", content.len()).as_bytes()); // size
        out.extend_from_slice(b"\x60\x0a"); // end marker
        out.extend_from_slice(content);
        if content.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn ar_exact_boundary_at_end_of_data() {
        let mut core = b"!<arch>\n".to_vec();
        core.extend_from_slice(&build_ar_entry("hello.txt", b"hello world")); // непарна довжина -> доповнення
        core.extend_from_slice(&build_ar_entry("second", b"data"));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_ar(&data, start).expect("valid ar must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn ar_truncated_falls_back_to_lower_confidence() {
        let mut core = b"!<arch>\n".to_vec();
        core.extend_from_slice(&build_ar_entry("hello.txt", b"hello world"));
        let first_entry_end = core.len();
        core.extend_from_slice(&build_ar_entry("second", b"data"));
        let truncated = &core[..first_entry_end + 30]; // другий запис обрізаний посеред заголовка

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(truncated);
        let expected_last_good_end = start + first_entry_end - 1;

        let (end, confidence) = validate_ar(&data, start).expect("partial ar still yields last entry end");
        assert_eq!(end, expected_last_good_end);
        assert_eq!(confidence, 70);
    }

    fn build_minimal_iso9660(volume_space_size: u32, logical_block_size: u16) -> Vec<u8> {
        let mut out = vec![0u8; 32768]; // системна область, заповнення до сектора 16
        let mut pvd = vec![0u8; 2048];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[80..84].copy_from_slice(&volume_space_size.to_le_bytes());
        pvd[84..88].copy_from_slice(&volume_space_size.to_be_bytes());
        pvd[128..130].copy_from_slice(&logical_block_size.to_le_bytes());
        pvd[130..132].copy_from_slice(&logical_block_size.to_be_bytes());
        out.extend_from_slice(&pvd);
        out
    }

    #[test]
    fn iso9660_exact_boundary() {
        // volume_space_size(20)×logical_block_size(2048)=40960 — обов'язково
        // більше за системну область+PVD (32768+2048=34816), інакше немає
        // куди "дописати" решту образу.
        let mut core = build_minimal_iso9660(20, 2048);
        core.resize(40960, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_iso9660(&data, start).expect("valid iso9660 must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn iso9660_truncated_returns_none() {
        let core = build_minimal_iso9660(20, 2048); // заявлений повний розмір 40960
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core); // лише системна область+PVD (34816), без решти образу
        assert_eq!(validate_iso9660(&data, start), None);
    }

    fn build_zstd_block(last_block: bool, block_type: u32, size: u32) -> Vec<u8> {
        let header = last_block as u32 | (block_type << 1) | (size << 3);
        vec![
            (header & 0xFF) as u8,
            ((header >> 8) & 0xFF) as u8,
            ((header >> 16) & 0xFF) as u8,
        ]
    }

    #[test]
    fn zstd_exact_boundary_single_raw_block() {
        let mut core = b"\x28\xb5\x2f\xfd".to_vec();
        core.push(0x00); // FHD: усі прапорці 0
        core.push(0x00); // Window_Descriptor
        core.extend_from_slice(&build_zstd_block(true, 0, 20)); // Raw_Block, останній
        core.extend(std::iter::repeat_n(0xABu8, 20));

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_zstd(&data, start).expect("valid zstd must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn zstd_single_segment_with_content_checksum() {
        let fhd: u8 = 0x04 | 0x20; // content_checksum_flag + single_segment_flag, fcs_flag=0 -> 1-байтове поле розміру
        let mut core = b"\x28\xb5\x2f\xfd".to_vec();
        core.push(fhd);
        core.push(5); // Frame_Content_Size (1 байт)
        core.extend_from_slice(&build_zstd_block(true, 2, 15)); // Compressed_Block, останній
        core.extend(std::iter::repeat_n(0xCDu8, 15));
        core.extend_from_slice(&[0u8; 4]); // Content_Checksum

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_zstd(&data, start).expect("valid zstd (single segment) must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn zstd_truncated_returns_none() {
        let mut core = b"\x28\xb5\x2f\xfd".to_vec();
        core.push(0x00);
        core.push(0x00);
        core.extend_from_slice(&build_zstd_block(true, 0, 20));
        core.extend(std::iter::repeat_n(0xABu8, 20));

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_zstd(&data, start), None);
    }

    fn build_wad_lump(name: &[u8; 8], filepos: u32, size: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&filepos.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(name);
        out
    }

    fn build_minimal_wad(lumps: &[u8]) -> Vec<u8> {
        let mut out = b"IWAD".to_vec();
        out.extend_from_slice(&1u32.to_le_bytes()); // numlumps
        let infotableofs = (12 + lumps.len()) as u32;
        out.extend_from_slice(&infotableofs.to_le_bytes());
        out.extend_from_slice(lumps);
        out.extend_from_slice(&build_wad_lump(b"LUMP1\0\0\0", 12, lumps.len() as u32));
        out
    }

    #[test]
    fn wad_exact_boundary() {
        let core = build_minimal_wad(b"HELLOWORLD");
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_wad(&data, start).expect("valid wad must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn wad_truncated_returns_none() {
        let core = build_minimal_wad(b"HELLOWORLD");
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_wad(&data, start), None);
    }

    fn build_pak_entry(name: &str, filepos: u32, filelength: u32) -> Vec<u8> {
        let mut out = vec![0u8; 56];
        out[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&filepos.to_le_bytes());
        out.extend_from_slice(&filelength.to_le_bytes());
        out
    }

    fn build_minimal_pak(content: &[u8]) -> Vec<u8> {
        let mut out = b"PACK".to_vec();
        let diroffset = (12 + content.len()) as u32;
        out.extend_from_slice(&diroffset.to_le_bytes());
        out.extend_from_slice(&64u32.to_le_bytes()); // dirlen: один запис
        out.extend_from_slice(content);
        out.extend_from_slice(&build_pak_entry("maps/e1m1.bsp", 12, content.len() as u32));
        out
    }

    #[test]
    fn pak_exact_boundary() {
        let core = build_minimal_pak(b"quakecontentdata");
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_pak_quake(&data, start).expect("valid pak must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn pak_truncated_returns_none() {
        let core = build_minimal_pak(b"quakecontentdata");
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_pak_quake(&data, start), None);
    }

    fn build_vbsp_lump(fileofs: u32, filelen: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&fileofs.to_le_bytes());
        out.extend_from_slice(&filelen.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // version
        out.extend_from_slice(&0u32.to_le_bytes()); // fourCC
        out
    }

    fn build_minimal_vbsp(lump_data: &[(u32, u32)]) -> Vec<u8> {
        let mut out = b"VBSP".to_vec();
        out.extend_from_slice(&20u32.to_le_bytes()); // version
        for i in 0..17 {
            let (ofs, len) = lump_data.get(i).copied().unwrap_or((0, 0));
            out.extend_from_slice(&build_vbsp_lump(ofs, len));
        }
        out
    }

    #[test]
    fn vbsp_exact_boundary() {
        let mut core = build_minimal_vbsp(&[(280, 500)]); // lump0 займає [280,780)
        core.resize(780, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_vbsp(&data, start).expect("valid vbsp must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    #[test]
    fn vbsp_truncated_returns_none() {
        let core = build_minimal_vbsp(&[(280, 500)]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core); // лише заголовок, без даних lump'а
        assert_eq!(validate_vbsp(&data, start), None);
    }

    fn build_minimal_nes(prg_units: u8, chr_units: u8, trainer: bool) -> Vec<u8> {
        let mut out = b"NES\x1a".to_vec();
        out.push(prg_units);
        out.push(chr_units);
        out.push(if trainer { 0x04 } else { 0x00 }); // flags6
        out.push(0); // flags7
        out.extend(std::iter::repeat_n(0u8, 8)); // padding до 16 байт
        if trainer {
            out.extend(std::iter::repeat_n(0u8, 512));
        }
        out.extend(std::iter::repeat_n(0xABu8, prg_units as usize * 16384));
        out.extend(std::iter::repeat_n(0xCDu8, chr_units as usize * 8192));
        out
    }

    #[test]
    fn nes_exact_boundary() {
        let core = build_minimal_nes(1, 1, false);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_nes(&data, start).expect("valid nes must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn nes_with_trainer_exact_boundary() {
        let core = build_minimal_nes(1, 0, true);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_nes(&data, start).expect("valid nes must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn nes_truncated_returns_none() {
        let core = build_minimal_nes(1, 1, false);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 100]);
        assert_eq!(validate_nes(&data, start), None);
    }

    fn build_minimal_unityfs(total_size: i64) -> Vec<u8> {
        let mut out = b"UnityFS\0".to_vec();
        out.extend_from_slice(&6u32.to_be_bytes()); // version
        out.extend_from_slice(b"5.6.0f1\0"); // unityVersion
        out.extend_from_slice(b"2018.4.0f1\0"); // unityRevision
        out.extend_from_slice(&total_size.to_be_bytes());
        out
    }

    #[test]
    fn unityfs_exact_boundary() {
        let mut core = build_minimal_unityfs(500);
        core.resize(500, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_unityfs(&data, start).expect("valid unityfs must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn unityfs_truncated_returns_none() {
        let mut core = build_minimal_unityfs(500);
        core.resize(500, 0xAB);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_unityfs(&data, start), None);
    }

    fn build_minimal_vpk(tree: &[u8], file_data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x34, 0x12, 0xAA, 0x55];
        out.extend_from_slice(&2u32.to_le_bytes()); // version
        out.extend_from_slice(&(tree.len() as u32).to_le_bytes());
        out.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // archiveMD5SectionSize
        out.extend_from_slice(&0u32.to_le_bytes()); // otherMD5SectionSize
        out.extend_from_slice(&0u32.to_le_bytes()); // signatureSectionSize
        out.extend_from_slice(tree);
        out.extend_from_slice(file_data);
        out
    }

    #[test]
    fn vpk_exact_boundary() {
        let core = build_minimal_vpk(&[0u8; 50], &[0xABu8; 200]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_vpk(&data, start).expect("valid vpk must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn vpk_v1_not_supported_returns_none() {
        let mut core = vec![0x34, 0x12, 0xAA, 0x55];
        core.extend_from_slice(&1u32.to_le_bytes()); // version=1 -> непідтримувано валідатором
        core.extend_from_slice(&0u32.to_le_bytes());
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_vpk(&data, start), None);
    }

    #[test]
    fn vpk_truncated_returns_none() {
        let core = build_minimal_vpk(&[0u8; 50], &[0xABu8; 200]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_vpk(&data, start), None);
    }

    fn build_swf_fws(body: &[u8]) -> Vec<u8> {
        let file_length = (8 + body.len()) as u32;
        let mut out = b"FWS".to_vec();
        out.push(6); // version
        out.extend_from_slice(&file_length.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn swf_fws_exact_boundary() {
        let core = build_swf_fws(&[0xAB; 40]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_swf(&data, start).expect("valid fws must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 95);
    }

    fn build_swf_cws(body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();

        let file_length = (8 + body.len()) as u32; // за специфікацією — розмір розпакованих даних
        let mut out = b"CWS".to_vec();
        out.push(6);
        out.extend_from_slice(&file_length.to_le_bytes());
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn swf_cws_exact_boundary() {
        let core = build_swf_cws(b"some repeated swf tag data ".repeat(50).as_slice());
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_swf(&data, start).expect("valid cws must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn swf_cws_truncated_returns_none() {
        let core = build_swf_cws(b"some repeated swf tag data ".repeat(50).as_slice());
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_swf(&data, start), None);
    }

    #[test]
    fn swf_zws_not_supported_returns_none() {
        let mut core = b"ZWS".to_vec();
        core.push(6);
        core.extend_from_slice(&100u32.to_le_bytes());
        core.extend_from_slice(&[0xAB; 20]);
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_swf(&data, start), None);
    }

    fn build_minimal_rifx(form_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = b"RIFX".to_vec();
        let chunk_size = 4 + payload.len() as u32;
        out.extend_from_slice(&chunk_size.to_be_bytes());
        out.extend_from_slice(form_type);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn rifx_exact_boundary() {
        let core = build_minimal_rifx(b"MV93", &[0xAB; 60]);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_rifx(&data, start).expect("valid rifx must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn rifx_truncated_returns_none() {
        let core = build_minimal_rifx(b"MV93", &[0xAB; 60]);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_rifx(&data, start), None);
    }

    fn build_rmf_chunk() -> Vec<u8> {
        let mut out = b".RMF".to_vec();
        out.extend_from_slice(&18u32.to_be_bytes()); // size
        out.extend_from_slice(&0u16.to_be_bytes()); // object_version
        out.extend_from_slice(&0u32.to_be_bytes()); // file_version
        out.extend_from_slice(&2u32.to_be_bytes()); // num_headers (включно з цим чанком)
        out
    }

    fn build_generic_rm_chunk(id: &[u8; 4], payload_len: usize) -> Vec<u8> {
        let size = 10 + payload_len as u32;
        let mut out = id.to_vec();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // version
        out.extend(std::iter::repeat_n(0u8, payload_len));
        out
    }

    #[test]
    fn realmedia_exact_boundary() {
        let mut core = build_rmf_chunk();
        core.extend_from_slice(&build_generic_rm_chunk(b"DATA", 100));
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_realmedia(&data, start).expect("valid realmedia must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 80);
    }

    #[test]
    fn realmedia_truncated_returns_none() {
        let mut core = build_rmf_chunk();
        core.extend_from_slice(&build_generic_rm_chunk(b"DATA", 100));
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_realmedia(&data, start), None);
    }

    fn build_minimal_voc(blocks: &[u8]) -> Vec<u8> {
        let mut out = b"Creative Voice File\x1a".to_vec();
        out.extend_from_slice(&26u16.to_le_bytes()); // header_size
        out.extend_from_slice(&0x010au16.to_le_bytes()); // version (довільне)
        out.extend_from_slice(&0u16.to_le_bytes()); // checksum
        out.extend_from_slice(blocks);
        out
    }

    fn build_voc_data_block(payload_len: usize) -> Vec<u8> {
        let size = 2 + payload_len as u32; // частота(1)+код стиснення(1)+дані
        let mut out = vec![1u8]; // block_type=1: Sound data
        out.push((size & 0xFF) as u8);
        out.push(((size >> 8) & 0xFF) as u8);
        out.push(((size >> 16) & 0xFF) as u8);
        out.push(0); // частота
        out.push(0); // код стиснення
        out.extend(std::iter::repeat_n(0xABu8, payload_len));
        out
    }

    #[test]
    fn voc_exact_boundary() {
        let mut blocks = build_voc_data_block(50);
        blocks.push(0); // Terminator
        let core = build_minimal_voc(&blocks);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_voc(&data, start).expect("valid voc must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn voc_truncated_returns_none() {
        let mut blocks = build_voc_data_block(50);
        blocks.push(0);
        let core = build_minimal_voc(&blocks);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_voc(&data, start), None);
    }

    fn encode_vint(value: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        for i in (0..len).rev() {
            bytes[i] = (value >> (8 * (len - 1 - i))) as u8;
        }
        bytes[0] |= 1u8 << (8 - len);
        bytes
    }

    fn build_ebml_element(id: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.extend_from_slice(&encode_vint(content.len() as u64, 4));
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn ebml_exact_boundary() {
        let ebml_header = build_ebml_element(b"\x1a\x45\xdf\xa3", &[0u8; 20]);
        let segment = build_ebml_element(b"\x18\x53\x80\x67", &vec![0xABu8; 300]);
        let mut core = ebml_header;
        core.extend_from_slice(&segment);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ebml(&data, start).expect("valid ebml must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn ebml_truncated_returns_none() {
        let ebml_header = build_ebml_element(b"\x1a\x45\xdf\xa3", &[0u8; 20]);
        let segment = build_ebml_element(b"\x18\x53\x80\x67", &vec![0xABu8; 300]);
        let mut core = ebml_header;
        core.extend_from_slice(&segment);

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_ebml(&data, start), None);
    }

    #[test]
    fn ebml_eight_byte_vint_does_not_panic() {
        // Реальні MKV/WebM (напр. з ffmpeg) майже завжди кодують розмір
        // Segment'а 8-байтовим VINT (перший байт = 0x01) — раніше це
        // спричиняло panic ("shift right with overflow") у read_ebml_vint.
        let ebml_header = build_ebml_element(b"\x1a\x45\xdf\xa3", &[0u8; 20]);
        let segment_content = vec![0xABu8; 300];
        let mut core = ebml_header;
        core.extend_from_slice(b"\x18\x53\x80\x67");
        core.extend_from_slice(&encode_vint(segment_content.len() as u64, 8));
        core.extend_from_slice(&segment_content);

        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_ebml(&data, start).expect("valid ebml with 8-byte vint must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn ebml_unknown_size_returns_none() {
        let ebml_header = build_ebml_element(b"\x1a\x45\xdf\xa3", &[0u8; 20]);
        let mut core = ebml_header;
        core.extend_from_slice(b"\x18\x53\x80\x67");
        core.push(0xFF); // 1-байтовий VINT з усіма використовними бітами=1 -> "невідомий розмір"
        core.extend(std::iter::repeat_n(0xABu8, 50));

        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_ebml(&data, start), None);
    }

    fn build_flv_tag(tag_type: u8, data_bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![tag_type];
        let size = data_bytes.len() as u32;
        out.push((size >> 16) as u8);
        out.push((size >> 8) as u8);
        out.push(size as u8);
        out.extend_from_slice(&[0u8; 3]); // timestamp
        out.push(0); // timestamp extended
        out.extend_from_slice(&[0u8; 3]); // stream id
        out.extend_from_slice(data_bytes);
        out
    }

    fn build_minimal_flv(tags: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"FLV".to_vec();
        out.push(1); // version
        out.push(0x01); // flags: є відео
        out.extend_from_slice(&9u32.to_be_bytes()); // header_size
        out.extend_from_slice(&0u32.to_be_bytes()); // PreviousTagSize0 = 0
        for tag in tags {
            out.extend_from_slice(tag);
            out.extend_from_slice(&(tag.len() as u32).to_be_bytes()); // PreviousTagSize для щойно записаного тега
        }
        out
    }

    #[test]
    fn flv_exact_boundary_at_end_of_data() {
        let tag1 = build_flv_tag(9, &[0xAB; 40]);
        let core = build_minimal_flv(&[tag1]);

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);

        let (end, confidence) = validate_flv(&data, start).expect("valid flv must parse");
        assert_eq!(end, data.len() - 1);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn flv_with_trailing_garbage_falls_back_to_lower_confidence() {
        let tag1 = build_flv_tag(9, &[0xAB; 40]);
        let core = build_minimal_flv(&[tag1]);
        let expected_last_good_end = 9 + 4 + 11 + 40 - 1; // header+PrevTagSize0+tag1-заголовок+tag1-дані-1

        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);
        data.extend_from_slice(b"NOTAVALIDFLVTAGHEADERBYTES");

        let (end, confidence) = validate_flv(&data, start).expect("partial flv still yields last tag end");
        assert_eq!(end, start + expected_last_good_end);
        assert_eq!(confidence, 70);
    }

    #[test]
    fn flv_no_valid_tag_returns_none() {
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(b"FLV\x01\x01");
        data.extend_from_slice(&9u32.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0]); // менше 4 байт для PreviousTagSize0
        assert_eq!(validate_flv(&data, start), None);
    }

    #[test]
    fn extract_cpio_newc_name_reads_name_field() {
        let core = build_cpio_newc_entry("hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_cpio_newc_name(&data, start), Some("hello.txt".to_string()));
    }

    #[test]
    fn extract_cpio_newc_name_reads_trailer() {
        let core = build_cpio_newc_entry("TRAILER!!!", b"");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_cpio_newc_name(&data, start), Some("TRAILER!!!".to_string()));
    }

    #[test]
    fn extract_cpio_odc_name_reads_name_field() {
        let core = build_cpio_odc_entry("hello.txt", b"hello world");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_cpio_odc_name(&data, start), Some("hello.txt".to_string()));
    }

    #[test]
    fn extract_ar_name_reads_first_entry() {
        let mut core = b"!<arch>\n".to_vec();
        core.extend_from_slice(&build_ar_entry("hello.txt", b"hello world"));
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core);
        assert_eq!(extract_ar_name(&data, start), Some("hello.txt".to_string()));
    }

    #[test]
    fn extract_wad_name_reads_first_directory_entry() {
        let core = build_minimal_wad(b"HELLOWORLD");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_wad_name(&data, start), Some("LUMP1".to_string()));
    }

    #[test]
    fn extract_pak_name_reads_first_directory_entry() {
        let core = build_minimal_pak(b"quakecontentdata");
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(extract_pak_name(&data, start), Some("maps/e1m1.bsp".to_string()));
    }

    fn build_minimal_woff(magic: &[u8; 4], total_len: u32) -> Vec<u8> {
        let mut out = magic.to_vec();
        out.extend_from_slice(b"true"); // flavor (довільне)
        out.extend_from_slice(&total_len.to_be_bytes());
        out.resize(total_len as usize, 0xAB);
        out
    }

    #[test]
    fn woff_exact_boundary() {
        let core = build_minimal_woff(b"wOFF", 300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_woff(&data, start).expect("valid woff must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn woff2_exact_boundary() {
        let core = build_minimal_woff(b"wOF2", 300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_woff(&data, start).expect("valid woff2 must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn woff_truncated_returns_none() {
        let core = build_minimal_woff(b"wOFF", 300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_woff(&data, start), None);
    }

    fn build_minimal_glb(total_len: u32) -> Vec<u8> {
        let mut out = b"glTF".to_vec();
        out.extend_from_slice(&2u32.to_le_bytes()); // version
        out.extend_from_slice(&total_len.to_le_bytes());
        out.resize(total_len as usize, 0xAB);
        out
    }

    #[test]
    fn glb_exact_boundary() {
        let core = build_minimal_glb(300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_glb(&data, start).expect("valid glb must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn glb_truncated_returns_none() {
        let core = build_minimal_glb(300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_glb(&data, start), None);
    }

    fn build_minimal_mpq(archive_size: u32) -> Vec<u8> {
        let mut out = b"MPQ\x1a".to_vec();
        out.extend_from_slice(&32u32.to_le_bytes()); // header_size (довільне)
        out.extend_from_slice(&archive_size.to_le_bytes());
        out.resize(archive_size as usize, 0xAB);
        out
    }

    #[test]
    fn mpq_exact_boundary() {
        let core = build_minimal_mpq(300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_mpq(&data, start).expect("valid mpq must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn mpq_truncated_returns_none() {
        let core = build_minimal_mpq(300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_mpq(&data, start), None);
    }

    fn build_minimal_squashfs(bytes_used: u64) -> Vec<u8> {
        let mut out = b"hsqs".to_vec();
        out.extend(std::iter::repeat_n(0u8, 36)); // поля до bytes_used (офсет 4..40)
        out.extend_from_slice(&bytes_used.to_le_bytes()); // офсет 40..48
        out.resize(bytes_used as usize, 0xAB);
        out
    }

    #[test]
    fn squashfs_exact_boundary() {
        let core = build_minimal_squashfs(200);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_squashfs(&data, start).expect("valid squashfs must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn squashfs_truncated_returns_none() {
        let core = build_minimal_squashfs(200);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_squashfs(&data, start), None);
    }

    fn build_minimal_cab(cb_cabinet: u32) -> Vec<u8> {
        let mut out = b"MSCF".to_vec();
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        out.extend_from_slice(&cb_cabinet.to_le_bytes());
        out.resize(cb_cabinet as usize, 0xAB);
        out
    }

    #[test]
    fn cab_exact_boundary() {
        let core = build_minimal_cab(300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_cab(&data, start).expect("valid cab must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn cab_truncated_returns_none() {
        let core = build_minimal_cab(300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_cab(&data, start), None);
    }

    fn build_minimal_dex(file_size: u32) -> Vec<u8> {
        let mut out = b"dex\n035\0".to_vec();
        out.extend_from_slice(&0u32.to_le_bytes()); // checksum
        out.extend(std::iter::repeat_n(0u8, 20)); // signature
        out.extend_from_slice(&file_size.to_le_bytes());
        out.resize(file_size as usize, 0xAB);
        out
    }

    #[test]
    fn dex_exact_boundary() {
        let core = build_minimal_dex(300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_dex(&data, start).expect("valid dex must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn dex_truncated_returns_none() {
        let core = build_minimal_dex(300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_dex(&data, start), None);
    }

    fn build_minimal_dpx(is_be: bool, file_size: u32) -> Vec<u8> {
        let mut out = if is_be { b"SDPX".to_vec() } else { b"XPDS".to_vec() };
        out.extend_from_slice(&0u32.to_le_bytes()); // offset_to_image (не критично)
        out.extend(std::iter::repeat_n(0u8, 8)); // version
        if is_be {
            out.extend_from_slice(&file_size.to_be_bytes());
        } else {
            out.extend_from_slice(&file_size.to_le_bytes());
        }
        out.resize(file_size as usize, 0xAB);
        out
    }

    #[test]
    fn dpx_be_exact_boundary() {
        let core = build_minimal_dpx(true, 300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_dpx_be(&data, start).expect("valid dpx (be) must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn dpx_le_exact_boundary() {
        let core = build_minimal_dpx(false, 300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_dpx_le(&data, start).expect("valid dpx (le) must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn dpx_truncated_returns_none() {
        let core = build_minimal_dpx(true, 300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_dpx_be(&data, start), None);
    }

    fn build_minimal_icc(profile_size: u32) -> Vec<u8> {
        let mut out = profile_size.to_be_bytes().to_vec();
        out.resize(36, 0u8);
        out.extend_from_slice(b"acsp");
        out.resize(profile_size as usize, 0xAB);
        out
    }

    #[test]
    fn icc_exact_boundary() {
        let core = build_minimal_icc(300);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_icc(&data, start).expect("valid icc must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn icc_truncated_returns_none() {
        let core = build_minimal_icc(300);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_icc(&data, start), None);
    }

    fn build_apple_entry(id: u32, offset: u32, length: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out
    }

    fn build_minimal_apple_single(entries: &[(u32, u32, u32)]) -> Vec<u8> {
        let mut out = 0x0005_1600u32.to_be_bytes().to_vec(); // magic
        out.extend_from_slice(&0x0002_0000u32.to_be_bytes()); // version
        out.extend(std::iter::repeat_n(0u8, 16)); // filler
        out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for &(id, offset, length) in entries {
            out.extend_from_slice(&build_apple_entry(id, offset, length));
        }
        out
    }

    #[test]
    fn apple_single_exact_boundary() {
        let mut core = build_minimal_apple_single(&[(1, 50, 100), (2, 150, 200)]);
        core.resize(350, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_apple_single_double(&data, start).expect("valid applesingle must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn apple_double_truncated_returns_none() {
        let mut core = build_minimal_apple_single(&[(1, 50, 100), (2, 150, 200)]);
        core.resize(350, 0xAB);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_apple_single_double(&data, start), None);
    }

    fn build_blend_block(code: &[u8; 4], is_be: bool, ptr_size: usize, payload_len: usize) -> Vec<u8> {
        let mut out = code.to_vec();
        let size = payload_len as u32;
        if is_be {
            out.extend_from_slice(&size.to_be_bytes());
        } else {
            out.extend_from_slice(&size.to_le_bytes());
        }
        out.extend(std::iter::repeat_n(0u8, ptr_size)); // old_address
        out.extend_from_slice(&0u32.to_le_bytes()); // SDNAindex
        out.extend_from_slice(&0u32.to_le_bytes()); // count
        out.extend(std::iter::repeat_n(0xABu8, payload_len));
        out
    }

    fn build_minimal_blend(ptr_size_char: u8, endian_char: u8, is_be: bool, ptr_size: usize) -> Vec<u8> {
        let mut out = b"BLENDER".to_vec();
        out.push(ptr_size_char);
        out.push(endian_char);
        out.extend_from_slice(b"280"); // версія
        out.extend_from_slice(&build_blend_block(b"DATA", is_be, ptr_size, 50));
        out.extend_from_slice(&build_blend_block(b"ENDB", is_be, ptr_size, 0));
        out
    }

    #[test]
    fn blend_exact_boundary_little_endian_32bit_ptr() {
        let core = build_minimal_blend(b'_', b'v', false, 4);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_blend(&data, start).expect("valid blend must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn blend_exact_boundary_big_endian_64bit_ptr() {
        let core = build_minimal_blend(b'-', b'V', true, 8);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_blend(&data, start).expect("valid blend must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 85);
    }

    #[test]
    fn blend_truncated_returns_none() {
        let core = build_minimal_blend(b'_', b'v', false, 4);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 5]);
        assert_eq!(validate_blend(&data, start), None);
    }

    fn build_minimal_au(data_offset: u32, data_size: u32) -> Vec<u8> {
        let mut out = b".snd".to_vec();
        out.extend_from_slice(&data_offset.to_be_bytes());
        out.extend_from_slice(&data_size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // encoding
        out.extend_from_slice(&0u32.to_be_bytes()); // sample_rate
        out.extend_from_slice(&0u32.to_be_bytes()); // channels
        out.resize((data_offset + data_size) as usize, 0xAB);
        out
    }

    #[test]
    fn au_exact_boundary() {
        let core = build_minimal_au(24, 100);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;
        let (end, confidence) = validate_au(&data, start).expect("valid au must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn au_unknown_size_returns_none() {
        let mut core = b".snd".to_vec();
        core.extend_from_slice(&24u32.to_be_bytes());
        core.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        core.extend_from_slice(&[0u8; 12]);
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_au(&data, start), None);
    }

    #[test]
    fn au_truncated_returns_none() {
        let core = build_minimal_au(24, 100);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_au(&data, start), None);
    }

    fn build_minimal_sfnt(num_tables: u16, table_entries: &[(u32, u32)]) -> Vec<u8> {
        let entry_selector = 15 - (num_tables | 1).leading_zeros() as u16;
        let search_range = (1u16 << entry_selector).wrapping_mul(16);
        let range_shift = num_tables.wrapping_mul(16).wrapping_sub(search_range);

        let mut out = vec![0u8; 4]; // sfnt version (не перевіряється валідатором)
        out.extend_from_slice(&num_tables.to_be_bytes());
        out.extend_from_slice(&search_range.to_be_bytes());
        out.extend_from_slice(&entry_selector.to_be_bytes());
        out.extend_from_slice(&range_shift.to_be_bytes());

        for &(offset, length) in table_entries {
            out.extend_from_slice(b"TEST"); // tag
            out.extend_from_slice(&0u32.to_be_bytes()); // checksum
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
        }
        out
    }

    #[test]
    fn sfnt_exact_boundary() {
        let mut core = build_minimal_sfnt(2, &[(44, 100), (144, 200)]);
        core.resize(344, 0xAB);
        let (data, start) = wrap_with_junk(&core);
        let expected_end = start + core.len() - 1;

        let (end, confidence) = validate_sfnt(&data, start).expect("valid sfnt must parse");
        assert_eq!(end, expected_end);
        assert_eq!(confidence, 90);
    }

    #[test]
    fn sfnt_rejects_invalid_invariants() {
        // Це саме той клас хибних збігів, що спричиняв шум на реальних
        // бінарних файлах (ROM-и, виконувані файли) до додавання цього
        // валідатора — довільні байти, що випадково почалися з
        // "00 01 00 00", але не задовольняють інваріантів sfnt-заголовка.
        let mut core = build_minimal_sfnt(2, &[(44, 100)]);
        core[6] = 0xFF; // псує searchRange
        let (data, start) = wrap_with_junk(&core);
        assert_eq!(validate_sfnt(&data, start), None);
    }

    #[test]
    fn sfnt_zero_tables_returns_none() {
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&[0u8; 12]);
        assert_eq!(validate_sfnt(&data, start), None);
    }

    #[test]
    fn sfnt_truncated_returns_none() {
        let mut core = build_minimal_sfnt(2, &[(44, 100), (144, 200)]);
        core.resize(344, 0xAB);
        let mut data = b"JUNK-PREFIX-".to_vec();
        let start = data.len();
        data.extend_from_slice(&core[..core.len() - 10]);
        assert_eq!(validate_sfnt(&data, start), None);
    }

    fn entry_names(entries: &[ArchiveEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn list_zip_entries_reads_name_and_size() {
        let core = build_minimal_zip(b"hello.txt", b"hello world");
        let entries = list_archive_entries("ZIP", &core).expect("zip must list entries");
        assert_eq!(entry_names(&entries), vec!["hello.txt"]);
        assert_eq!(entries[0].size, 11);
    }

    #[test]
    fn list_tar_entries_reads_name_and_size() {
        let core = build_minimal_tar("hello.txt", b"hello world");
        let entries = list_archive_entries("TAR", &core).expect("tar must list entries");
        assert_eq!(entry_names(&entries), vec!["hello.txt"]);
        assert_eq!(entries[0].size, 11);
    }

    #[test]
    fn list_cpio_newc_entries_lists_all_files_and_skips_trailer() {
        let mut core = build_cpio_newc_entry("a.txt", b"AAA");
        core.extend_from_slice(&build_cpio_newc_entry("b.txt", b"BB"));
        core.extend_from_slice(&build_cpio_newc_entry("TRAILER!!!", b""));

        let entries = list_archive_entries("CPIO-newc", &core).expect("cpio newc must list entries");
        assert_eq!(entry_names(&entries), vec!["a.txt", "b.txt"]);
        assert_eq!(entries[0].size, 3);
        assert_eq!(entries[1].size, 2);
    }

    #[test]
    fn list_cpio_odc_entries_lists_all_files_and_skips_trailer() {
        let mut core = build_cpio_odc_entry("a.txt", b"AAA");
        core.extend_from_slice(&build_cpio_odc_entry("b.txt", b"BB"));
        core.extend_from_slice(&build_cpio_odc_entry("TRAILER!!!", b""));

        let entries = list_archive_entries("CPIO-odc", &core).expect("cpio odc must list entries");
        assert_eq!(entry_names(&entries), vec!["a.txt", "b.txt"]);
        assert_eq!(entries[0].size, 3);
        assert_eq!(entries[1].size, 2);
    }

    #[test]
    fn list_ar_entries_lists_all_members() {
        let mut core = b"!<arch>\n".to_vec();
        core.extend_from_slice(&build_ar_entry("hello.txt", b"hello world"));
        core.extend_from_slice(&build_ar_entry("second", b"data"));

        let entries = list_archive_entries("AR", &core).expect("ar must list entries");
        assert_eq!(entry_names(&entries), vec!["hello.txt", "second"]);
        assert_eq!(entries[0].size, 11);
        assert_eq!(entries[1].size, 4);
    }

    #[test]
    fn list_wad_entries_reads_lump_directory() {
        let core = build_minimal_wad(b"HELLOWORLD");
        let entries = list_archive_entries("WAD-I", &core).expect("wad must list entries");
        assert_eq!(entry_names(&entries), vec!["LUMP1"]);
        assert_eq!(entries[0].size, 10);
    }

    #[test]
    fn list_pak_entries_reads_directory() {
        let core = build_minimal_pak(b"quakecontentdata");
        let entries = list_archive_entries("PAK-Quake", &core).expect("pak must list entries");
        assert_eq!(entry_names(&entries), vec!["maps/e1m1.bsp"]);
        assert_eq!(entries[0].size, 16);
    }

    #[test]
    fn list_archive_entries_returns_none_for_unsupported_format() {
        assert!(list_archive_entries("JPEG", b"whatever").is_none());
    }

    #[test]
    fn list_sfnt_tables_reads_tag_and_length() {
        let core = build_minimal_sfnt(2, &[(44, 100), (144, 200)]);
        let entries = list_archive_entries("TTF", &core).expect("sfnt must list tables");
        assert_eq!(entry_names(&entries), vec!["TEST", "TEST"]);
        assert_eq!(entries[0].size, 100);
        assert_eq!(entries[1].size, 200);
    }

    #[test]
    fn list_png_chunks_reads_type_and_length() {
        let core = build_minimal_png();
        let entries = list_archive_entries("PNG", &core).expect("png must list chunks");
        assert_eq!(entry_names(&entries), vec!["IHDR", "IEND"]);
        assert_eq!(entries[0].size, 13);
        assert_eq!(entries[1].size, 0);
    }

    #[test]
    fn list_riff_chunks_reads_subchunks() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"fmt ");
        payload.extend_from_slice(&16u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(b"data");
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        payload.push(0); // доповнення до парного розміру

        let core = build_minimal_riff(b"WAVE", &payload);
        let entries = list_archive_entries("WAV", &core).expect("riff must list chunks");
        assert_eq!(entry_names(&entries), vec!["fmt ", "data"]);
        assert_eq!(entries[0].size, 16);
        assert_eq!(entries[1].size, 3);
    }

    #[test]
    fn list_iff_chunks_reads_subchunks_big_endian() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"COMM");
        payload.extend_from_slice(&18u32.to_be_bytes());
        payload.extend_from_slice(&[0u8; 18]);
        payload.extend_from_slice(b"SSND");
        payload.extend_from_slice(&5u32.to_be_bytes());
        payload.extend_from_slice(&[1, 2, 3, 4, 5]);
        payload.push(0); // доповнення до парного розміру

        let core = build_minimal_iff(b"AIFF", &payload);
        let entries = list_archive_entries("AIFF", &core).expect("iff must list chunks");
        assert_eq!(entry_names(&entries), vec!["COMM", "SSND"]);
        assert_eq!(entries[0].size, 18);
        assert_eq!(entries[1].size, 5);
    }

    #[test]
    fn list_isobmff_boxes_reads_type_and_size() {
        let core = build_minimal_heic_boxes(); // ftyp(16) + meta(28) + mdat(108)
        let entries = list_archive_entries("HEIC", &core).expect("isobmff must list boxes");
        assert_eq!(entry_names(&entries), vec!["ftyp", "meta", "mdat"]);
        assert_eq!(entries[0].size, 16);
        assert_eq!(entries[1].size, 28);
        assert_eq!(entries[2].size, 108);
    }

    fn build_elf64_shdr(name: u32, sh_type: u32, offset: u64, size: u64) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(&name.to_le_bytes());
        out[4..8].copy_from_slice(&sh_type.to_le_bytes());
        out[24..32].copy_from_slice(&offset.to_le_bytes());
        out[32..40].copy_from_slice(&size.to_le_bytes());
        out
    }

    /// ELF64 з реальною таблицею рядків секцій (`.shstrtab`) — на відміну
    /// від `build_minimal_elf64` (лише для перевірки арифметики меж), тут
    /// імена секцій справді розв'язуються через `sh_name`, як робить
    /// `list_elf_sections` через `goblin`.
    fn build_elf64_with_named_sections(sections: &[(&str, u64)]) -> Vec<u8> {
        let mut e_ident = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0];
        e_ident.extend(std::iter::repeat_n(0u8, 7));

        let mut strtab = vec![0u8]; // офсет 0 — порожній рядок (секція SHT_NULL)
        let mut name_offsets = Vec::new();
        for (name, _) in sections {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        let shstrtab_name_offset = strtab.len() as u32;
        strtab.extend_from_slice(b".shstrtab");
        strtab.push(0);

        let num_sections = sections.len() + 2; // SHT_NULL + звичайні + .shstrtab
        let ehdr_size: u64 = 64;
        let strtab_offset = ehdr_size;
        let shoff = strtab_offset + strtab.len() as u64;

        let mut header = e_ident;
        header.extend_from_slice(&2u16.to_le_bytes()); // e_type
        header.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine: x86-64
        header.extend_from_slice(&1u32.to_le_bytes()); // e_version
        header.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        header.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        header.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        header.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        header.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        header.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        header.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        header.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        header.extend_from_slice(&(num_sections as u16).to_le_bytes()); // e_shnum
        header.extend_from_slice(&((num_sections - 1) as u16).to_le_bytes()); // e_shstrndx
        assert_eq!(header.len(), 64);

        let mut out = header;
        out.extend_from_slice(&strtab);

        out.extend_from_slice(&build_elf64_shdr(0, 0, 0, 0)); // SHT_NULL
        for ((_, size), &name_offset) in sections.iter().zip(&name_offsets) {
            out.extend_from_slice(&build_elf64_shdr(name_offset, 1, 0, *size)); // SHT_PROGBITS
        }
        out.extend_from_slice(&build_elf64_shdr(shstrtab_name_offset, 3, strtab_offset, strtab.len() as u64));

        out
    }

    #[test]
    fn list_elf_sections_reads_names_via_shstrtab() {
        let core = build_elf64_with_named_sections(&[(".text", 100), (".data", 20)]);
        let entries = list_archive_entries("ELF", &core).expect("elf must list sections");
        assert_eq!(entry_names(&entries), vec![".text", ".data", ".shstrtab"]);
        assert_eq!(entries[0].size, 100);
        assert_eq!(entries[1].size, 20);
    }

    #[test]
    fn list_pe_sections_reads_name_and_raw_size() {
        let core = build_minimal_pe32(64);
        let entries = list_archive_entries("PE", &core).expect("pe must list sections");
        assert_eq!(entry_names(&entries), vec![".text"]);
        assert_eq!(entries[0].size, 64);
    }

    fn build_lc_segment64_with_sections(is_be: bool, segname: &str, sections: &[(&str, u64)]) -> Vec<u8> {
        let nsects = sections.len() as u32;
        let cmdsize = 72 + 80 * nsects;
        let mut segname_bytes = segname.as_bytes().to_vec();
        segname_bytes.resize(16, 0);

        let mut out = Vec::new();
        put_u32(&mut out, 0x19, is_be); // LC_SEGMENT_64
        put_u32(&mut out, cmdsize, is_be);
        out.extend_from_slice(&segname_bytes);
        put_u64(&mut out, 0, is_be); // vmaddr
        put_u64(&mut out, 0, is_be); // vmsize
        put_u64(&mut out, 0, is_be); // fileoff
        put_u64(&mut out, 0, is_be); // filesize
        put_u32(&mut out, 0, is_be); // maxprot
        put_u32(&mut out, 0, is_be); // initprot
        put_u32(&mut out, nsects, is_be);
        put_u32(&mut out, 0, is_be); // flags

        for (name, size) in sections {
            let mut sectname = name.as_bytes().to_vec();
            sectname.resize(16, 0);
            out.extend_from_slice(&sectname);
            out.extend_from_slice(&segname_bytes);
            put_u64(&mut out, 0, is_be); // addr
            put_u64(&mut out, *size, is_be); // size
            put_u32(&mut out, 0, is_be); // offset
            put_u32(&mut out, 0, is_be); // align
            put_u32(&mut out, 0, is_be); // reloff
            put_u32(&mut out, 0, is_be); // nreloc
            put_u32(&mut out, 0, is_be); // flags
            put_u32(&mut out, 0, is_be); // reserved1
            put_u32(&mut out, 0, is_be); // reserved2
            put_u32(&mut out, 0, is_be); // reserved3
        }
        out
    }

    #[test]
    fn list_macho_sections_reads_segname_sectname_and_size() {
        let lc_seg = build_lc_segment64_with_sections(false, "__TEXT", &[("__text", 500), ("__cstring", 42)]);
        let header = build_mach_header64(false, 1, lc_seg.len() as u32);
        let mut core = header;
        core.extend_from_slice(&lc_seg);

        let entries = list_archive_entries("Mach-O-64-LE", &core).expect("macho must list sections");
        assert_eq!(entry_names(&entries), vec!["__TEXT,__text", "__TEXT,__cstring"]);
        assert_eq!(entries[0].size, 500);
        assert_eq!(entries[1].size, 42);
    }

    #[test]
    fn list_macho_fat_archs_reads_cputype_and_size() {
        let mut core = b"\xca\xfe\xba\xbe".to_vec();
        core.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch
        // arch 0: x86_64, розмір 1000
        core.extend_from_slice(&0x01000007u32.to_be_bytes());
        core.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        core.extend_from_slice(&0u32.to_be_bytes()); // offset
        core.extend_from_slice(&1000u32.to_be_bytes()); // size
        core.extend_from_slice(&0u32.to_be_bytes()); // align
        // arch 1: arm64, розмір 2000
        core.extend_from_slice(&0x0100000cu32.to_be_bytes());
        core.extend_from_slice(&0u32.to_be_bytes());
        core.extend_from_slice(&1000u32.to_be_bytes());
        core.extend_from_slice(&2000u32.to_be_bytes());
        core.extend_from_slice(&0u32.to_be_bytes());

        let entries = list_archive_entries("Mach-O-Fat", &core).expect("macho fat must list archs");
        assert_eq!(entry_names(&entries), vec!["x86_64", "arm64"]);
        assert_eq!(entries[0].size, 1000);
        assert_eq!(entries[1].size, 2000);
    }

    #[test]
    fn format_duration_formats_minutes_and_seconds() {
        assert_eq!(format_duration(65.4), "1:05");
        assert_eq!(format_duration(0.0), "0:00");
        assert_eq!(format_duration(f64::NAN), "н/д");
        assert_eq!(format_duration(-1.0), "н/д");
    }

    #[test]
    fn wav_facts_reads_channels_rate_bits_and_duration() {
        let mut fmt = Vec::new();
        fmt.extend_from_slice(&1u16.to_le_bytes()); // PCM
        fmt.extend_from_slice(&2u16.to_le_bytes()); // channels
        fmt.extend_from_slice(&44100u32.to_le_bytes()); // sample rate
        let byte_rate = 44100u32 * 2 * 2; // sampleRate * channels * bytesPerSample
        fmt.extend_from_slice(&byte_rate.to_le_bytes());
        fmt.extend_from_slice(&4u16.to_le_bytes()); // block align
        fmt.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

        let mut payload = b"WAVE".to_vec();
        payload.extend_from_slice(b"fmt ");
        payload.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
        payload.extend_from_slice(&fmt);
        let data_bytes = vec![0u8; byte_rate as usize]; // рівно 1 секунда
        payload.extend_from_slice(b"data");
        payload.extend_from_slice(&(data_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(&data_bytes);

        let mut core = b"RIFF".to_vec();
        core.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        core.extend_from_slice(&payload);

        let facts = format_facts("WAV", &core).expect("wav must produce facts");
        assert!(facts.contains("Канали: 2"), "{facts}");
        assert!(facts.contains("Частота дискретизації: 44100 Гц"), "{facts}");
        assert!(facts.contains("Розрядність: 16 біт"), "{facts}");
        assert!(facts.contains("Тривалість: 0:01"), "{facts}");
    }

    fn build_aiff_comm(channels: u16, num_frames: u32, sample_size: u16, sample_rate: f64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&channels.to_be_bytes());
        out.extend_from_slice(&num_frames.to_be_bytes());
        out.extend_from_slice(&sample_size.to_be_bytes());

        // Кодує 80-бітний розширений IEEE 754 із фіксованою експонентою 15
        // (після зняття зміщення 16383) — придатно для будь-якої цілої
        // частоти дискретизації < 65536 Гц: value = mantissa / 2^48.
        let exponent_stored: u16 = 16383 + 15;
        let mantissa = (sample_rate as u64) << 48;
        out.extend_from_slice(&exponent_stored.to_be_bytes());
        out.extend_from_slice(&mantissa.to_be_bytes());
        out
    }

    #[test]
    fn aiff_facts_reads_channels_rate_bits_and_duration() {
        let comm = build_aiff_comm(2, 44100, 16, 44100.0);
        let mut payload = b"COMM".to_vec();
        payload.extend_from_slice(&(comm.len() as u32).to_be_bytes());
        payload.extend_from_slice(&comm);

        let core = build_minimal_iff(b"AIFF", &payload);
        let facts = format_facts("AIFF", &core).expect("aiff must produce facts");
        assert!(facts.contains("Канали: 2"), "{facts}");
        assert!(facts.contains("Частота дискретизації: 44100 Гц"), "{facts}");
        assert!(facts.contains("Розрядність: 16 біт"), "{facts}");
        assert!(facts.contains("Тривалість: 0:01"), "{facts}");
    }

    #[test]
    fn au_facts_reads_channels_rate_bits_and_duration() {
        let mut core = b".snd".to_vec();
        core.extend_from_slice(&24u32.to_be_bytes()); // data_offset
        let sample_rate = 8000u32;
        let channels = 1u32;
        let duration_secs = 2u32;
        let data_size = sample_rate * channels * 2 * duration_secs; // 16-біт лінійний PCM
        core.extend_from_slice(&data_size.to_be_bytes());
        core.extend_from_slice(&3u32.to_be_bytes()); // encoding: 16-bit linear PCM
        core.extend_from_slice(&sample_rate.to_be_bytes());
        core.extend_from_slice(&channels.to_be_bytes());
        core.extend(std::iter::repeat_n(0u8, data_size as usize));

        let facts = format_facts("AU", &core).expect("au must produce facts");
        assert!(facts.contains("Канали: 1"), "{facts}");
        assert!(facts.contains("Частота дискретизації: 8000 Гц"), "{facts}");
        assert!(facts.contains("Розрядність: 16 біт"), "{facts}");
        assert!(facts.contains("Тривалість: 0:02"), "{facts}");
    }

    #[test]
    fn au_facts_does_not_panic_on_extreme_channels_and_sample_rate() {
        // channels/sample_rate — сирі 32-бітні поля без верхньої межі;
        // раніше їхній добуток міг переповнити `u64` і панікувати.
        let mut core = b".snd".to_vec();
        core.extend_from_slice(&24u32.to_be_bytes()); // data_offset
        core.extend_from_slice(&100u32.to_be_bytes()); // data_size
        core.extend_from_slice(&3u32.to_be_bytes()); // encoding: 16-bit linear PCM
        core.extend_from_slice(&u32::MAX.to_be_bytes()); // sample_rate
        core.extend_from_slice(&u32::MAX.to_be_bytes()); // channels

        let facts = format_facts("AU", &core).expect("au must still produce basic facts");
        assert!(!facts.contains("Тривалість"), "{facts}");
    }

    #[test]
    fn caf_facts_reads_channels_rate_and_bits_from_desc_chunk() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&48000f64.to_be_bytes());
        desc.extend_from_slice(b"lpcm");
        desc.extend_from_slice(&0u32.to_be_bytes()); // formatFlags
        desc.extend_from_slice(&4u32.to_be_bytes()); // bytesPerPacket
        desc.extend_from_slice(&1u32.to_be_bytes()); // framesPerPacket
        desc.extend_from_slice(&4u32.to_be_bytes()); // bytesPerFrame
        desc.extend_from_slice(&2u32.to_be_bytes()); // channelsPerFrame
        desc.extend_from_slice(&16u32.to_be_bytes()); // bitsPerChannel

        let mut core = b"caff".to_vec();
        core.extend_from_slice(&1u16.to_be_bytes()); // version
        core.extend_from_slice(&0u16.to_be_bytes()); // flags
        core.extend_from_slice(b"desc");
        core.extend_from_slice(&(desc.len() as i64).to_be_bytes());
        core.extend_from_slice(&desc);

        let facts = format_facts("CAF", &core).expect("caf must produce facts");
        assert!(facts.contains("Канали: 2"), "{facts}");
        assert!(facts.contains("Частота дискретизації: 48000 Гц"), "{facts}");
        assert!(facts.contains("Розрядність: 16 біт"), "{facts}");
    }

    fn build_minimal_flac_streaminfo(sample_rate: u32, channels: u32, bits_per_sample: u32, total_samples: u64) -> Vec<u8> {
        let mut core = b"fLaC".to_vec();
        core.push(0x80); // остання (і єдина) метадані-блок, тип 0 = STREAMINFO
        core.extend_from_slice(&34u32.to_be_bytes()[1..]); // довжина блоку, 3 байти BE

        let mut info = vec![0u8; 10]; // minBlockSize/maxBlockSize/minFrameSize/maxFrameSize (не перевіряються)
        let combined: u64 = ((sample_rate as u64) << 44)
            | (((channels - 1) as u64) << 41)
            | (((bits_per_sample - 1) as u64) << 36)
            | (total_samples & 0xF_FFFF_FFFF);
        info.extend_from_slice(&combined.to_be_bytes());
        info.extend(std::iter::repeat_n(0u8, 16)); // MD5 (не перевіряється)
        assert_eq!(info.len(), 34);

        core.extend_from_slice(&info);
        core
    }

    #[test]
    fn flac_facts_reads_packed_streaminfo_fields() {
        let core = build_minimal_flac_streaminfo(44100, 2, 16, 44100 * 3);
        let facts = format_facts("FLAC", &core).expect("flac must produce facts");
        assert!(facts.contains("Канали: 2"), "{facts}");
        assert!(facts.contains("Частота дискретизації: 44100 Гц"), "{facts}");
        assert!(facts.contains("Розрядність: 16 біт"), "{facts}");
        assert!(facts.contains("Тривалість: 0:03"), "{facts}");
    }

    #[test]
    fn dds_facts_reads_width_and_height() {
        let mut core = b"DDS ".to_vec();
        core.extend_from_slice(&124u32.to_le_bytes()); // dwSize
        core.extend_from_slice(&0u32.to_le_bytes()); // dwFlags
        core.extend_from_slice(&768u32.to_le_bytes()); // dwHeight
        core.extend_from_slice(&1024u32.to_le_bytes()); // dwWidth
        assert_eq!(format_facts("DDS", &core), Some("Роздільність: 1024×768".to_string()));
    }

    #[test]
    fn ktx_facts_reads_pixel_width_and_height() {
        let mut core = vec![0u8; 44];
        core[36..40].copy_from_slice(&256u32.to_le_bytes());
        core[40..44].copy_from_slice(&128u32.to_le_bytes());
        assert_eq!(format_facts("KTX", &core), Some("Роздільність: 256×128".to_string()));
    }

    #[test]
    fn ktx2_facts_reads_pixel_width_and_height() {
        let mut core = vec![0u8; 28];
        core[20..24].copy_from_slice(&512u32.to_le_bytes());
        core[24..28].copy_from_slice(&256u32.to_le_bytes());
        assert_eq!(format_facts("KTX2", &core), Some("Роздільність: 512×256".to_string()));
    }

    #[test]
    fn hdr_facts_reads_resolution_line() {
        let core = b"#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 200 +X 400\n".to_vec();
        assert_eq!(format_facts("HDR", &core), Some("Роздільність: 400×200".to_string()));
    }

    #[test]
    fn pvr_facts_reads_height_and_width() {
        let mut core = vec![0u8; 32];
        core[24..28].copy_from_slice(&64u32.to_le_bytes()); // height
        core[28..32].copy_from_slice(&128u32.to_le_bytes()); // width
        assert_eq!(format_facts("PVR", &core), Some("Роздільність: 128×64".to_string()));
    }

    #[test]
    fn nes_facts_reads_rom_sizes_mapper_and_mirroring() {
        // mapper 1 (MMC1): нижній нібл flags6 = 0001 (мапер молодша половина), flags7 верхня половина 0
        let core = vec![b'N', b'E', b'S', 0x1a, 2, 1, 0b0001_0001, 0x00];
        let facts = format_facts("NES", &core).expect("nes must produce facts");
        assert!(facts.contains("PRG ROM: 32 KiB"), "{facts}");
        assert!(facts.contains("CHR ROM: 8 KiB"), "{facts}");
        assert!(facts.contains("Мапер: 1"), "{facts}");
        assert!(facts.contains("Дзеркалення: вертикальне"), "{facts}");
    }

    #[test]
    fn genesis_facts_reads_domestic_title_and_region() {
        let mut core = vec![0u8; 0x1f3];
        core[0x120..0x120 + 11].copy_from_slice(b"TEST GAME 1");
        core[0x1f0..0x1f3].copy_from_slice(b"JUE");
        let facts = format_facts("Genesis", &core).expect("genesis must produce facts");
        assert!(facts.contains("Назва: TEST GAME 1"), "{facts}");
        assert!(facts.contains("Регіон: JUE"), "{facts}");
    }

    #[test]
    fn format_facts_returns_none_for_unsupported_format() {
        assert!(format_facts("JPEG", b"whatever").is_none());
    }

    fn build_sqlite_text_serial(s: &str) -> (i64, Vec<u8>) {
        (2 * s.len() as i64 + 13, s.as_bytes().to_vec())
    }

    /// Один рядок таблиці `sqlite_schema` (type/name/tbl_name/rootpage/sql).
    /// Спрощення: усі значення підібрані так, щоб кожен varint (довжина
    /// заголовка запису, кожен serial type) вміщувався в 1 байт.
    fn build_sqlite_schema_record(obj_type: &str, name: &str, tbl_name: &str, rootpage: u8, sql: &str) -> Vec<u8> {
        let (st_type, b_type) = build_sqlite_text_serial(obj_type);
        let (st_name, b_name) = build_sqlite_text_serial(name);
        let (st_tbl, b_tbl) = build_sqlite_text_serial(tbl_name);
        let (st_sql, b_sql) = build_sqlite_text_serial(sql);
        let serials = [st_type, st_name, st_tbl, 1i64, st_sql];

        let mut record = vec![(1 + serials.len()) as u8]; // varint(header_length)
        record.extend(serials.iter().map(|&s| s as u8));
        record.extend_from_slice(&b_type);
        record.extend_from_slice(&b_name);
        record.extend_from_slice(&b_tbl);
        record.push(rootpage);
        record.extend_from_slice(&b_sql);
        record
    }

    fn build_sqlite_cell(rowid: u8, record: &[u8]) -> Vec<u8> {
        let mut out = vec![record.len() as u8, rowid]; // varint(payload_length) + varint(rowid), обидва <128
        out.extend_from_slice(record);
        out
    }

    fn build_minimal_sqlite_schema(records: &[Vec<u8>]) -> Vec<u8> {
        const PAGE_SIZE: usize = 4096;
        const CELL_PTR_START: usize = 108;

        let mut file_header = vec![0u8; 100];
        file_header[0..16].copy_from_slice(b"SQLite format 3\0");
        file_header[16..18].copy_from_slice(&(PAGE_SIZE as u16).to_be_bytes());

        let cells: Vec<Vec<u8>> = records.iter().enumerate().map(|(i, r)| build_sqlite_cell(i as u8 + 1, r)).collect();
        let mut cell_data = Vec::new();
        let mut cell_offsets = Vec::new();
        let mut offset = CELL_PTR_START + cells.len() * 2;
        for cell in &cells {
            cell_offsets.push(offset as u16);
            cell_data.extend_from_slice(cell);
            offset += cell.len();
        }

        let mut page1 = file_header;
        page1.push(0x0d); // page type: leaf table b-tree
        page1.extend_from_slice(&0u16.to_be_bytes()); // first_freeblock
        page1.extend_from_slice(&(cells.len() as u16).to_be_bytes());
        page1.extend_from_slice(&0u16.to_be_bytes()); // cell_content_offset (не використовується читачем)
        page1.push(0); // fragmented_free_bytes
        for off in &cell_offsets {
            page1.extend_from_slice(&off.to_be_bytes());
        }
        page1.extend_from_slice(&cell_data);
        page1.resize(PAGE_SIZE, 0);
        page1
    }

    #[test]
    fn list_sqlite_entries_reads_schema_rows() {
        let record1 = build_sqlite_schema_record("table", "users", "users", 2, "CREATE TABLE users (id INTEGER)");
        let record2 = build_sqlite_schema_record("index", "idx_users", "users", 3, "CREATE INDEX idx_users ON users(id)");
        let core = build_minimal_sqlite_schema(&[record1, record2]);

        let entries = list_archive_entries("SQLite", &core).expect("sqlite must list schema");
        assert_eq!(entry_names(&entries), vec!["table: users", "index: idx_users"]);
        assert_eq!(entries[0].size, "CREATE TABLE users (id INTEGER)".len() as u64);
        assert_eq!(entries[1].size, "CREATE INDEX idx_users ON users(id)".len() as u64);
    }

    #[test]
    fn list_sqlite_entries_rejects_negative_varint_payload_length_without_panicking() {
        // 9 байт 0xFF декодуються `read_sqlite_varint` як -1 (i64) — крафтоване
        // значення, що раніше давало `payload_len as usize == usize::MAX` і
        // панікувало на `n1 + n2 + payload_len as usize` (переповнення додавання).
        let mut malicious_cell = vec![0xFFu8; 9];
        malicious_cell.push(1); // varint rowid = 1

        const PAGE_SIZE: usize = 4096;
        const CELL_PTR_START: usize = 108;
        let mut file_header = vec![0u8; 100];
        file_header[0..16].copy_from_slice(b"SQLite format 3\0");
        file_header[16..18].copy_from_slice(&(PAGE_SIZE as u16).to_be_bytes());

        let cell_offset = CELL_PTR_START + 2;
        let mut page1 = file_header;
        page1.push(0x0d);
        page1.extend_from_slice(&0u16.to_be_bytes());
        page1.extend_from_slice(&1u16.to_be_bytes()); // num_cells
        page1.extend_from_slice(&0u16.to_be_bytes());
        page1.push(0);
        page1.extend_from_slice(&(cell_offset as u16).to_be_bytes());
        page1.extend_from_slice(&malicious_cell);
        page1.resize(PAGE_SIZE, 0);

        // Головне — що виклик не панікує; коректний результат для недійсного
        // payload — `None`.
        assert!(list_archive_entries("SQLite", &page1).is_none());
    }

    fn build_iso9660_dir_record(name: &str, extent: u32, length: u32, is_dir: bool) -> Vec<u8> {
        let id_len = name.len();
        let mut record_len = 33 + id_len;
        if record_len % 2 == 1 {
            record_len += 1; // директорійні записи мають парну довжину (доповнення байтом)
        }
        let mut out = vec![0u8; record_len];
        out[0] = record_len as u8;
        out[2..6].copy_from_slice(&extent.to_le_bytes());
        out[6..10].copy_from_slice(&extent.to_be_bytes());
        out[10..14].copy_from_slice(&length.to_le_bytes());
        out[14..18].copy_from_slice(&length.to_be_bytes());
        out[25] = if is_dir { 0x02 } else { 0x00 };
        out[32] = id_len as u8;
        out[33..33 + id_len].copy_from_slice(name.as_bytes());
        out
    }

    fn build_minimal_iso9660_with_root(files: &[(&str, u32)]) -> Vec<u8> {
        const SECTOR: usize = 2048;
        let root_extent = 20u32;

        let mut dir_content = build_iso9660_dir_record("\0", root_extent, SECTOR as u32, true); // "."
        dir_content.extend_from_slice(&build_iso9660_dir_record("\x01", root_extent, SECTOR as u32, true)); // ".."
        for (name, size) in files {
            dir_content.extend_from_slice(&build_iso9660_dir_record(name, root_extent + 1, *size, false));
        }
        let dir_len = dir_content.len() as u32;

        let mut pvd = vec![0u8; SECTOR];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        let root_record = build_iso9660_dir_record("\0", root_extent, dir_len, true);
        pvd[156..156 + root_record.len()].copy_from_slice(&root_record);

        let total_sectors = root_extent as usize + 2;
        let mut image = vec![0u8; total_sectors * SECTOR];
        image[16 * SECTOR..16 * SECTOR + SECTOR].copy_from_slice(&pvd);
        image[root_extent as usize * SECTOR..root_extent as usize * SECTOR + dir_content.len()].copy_from_slice(&dir_content);
        image
    }

    #[test]
    fn list_iso9660_entries_reads_root_level_files() {
        let core = build_minimal_iso9660_with_root(&[("README.TXT;1", 1234), ("DATA.BIN;1", 5678)]);
        let entries = list_archive_entries("ISO9660", &core).expect("iso9660 must list root files");
        assert_eq!(entry_names(&entries), vec!["README.TXT", "DATA.BIN"]);
        assert_eq!(entries[0].size, 1234);
        assert_eq!(entries[1].size, 5678);
    }

    fn build_vpk_tree_entry(entry_length: u32) -> Vec<u8> {
        let mut out = vec![0u8; 8]; // CRC(4) + PreloadBytes(2) + ArchiveIndex(2)
        out.extend_from_slice(&0u32.to_le_bytes()); // EntryOffset
        out.extend_from_slice(&entry_length.to_le_bytes());
        out.extend_from_slice(&0xffffu16.to_le_bytes()); // Terminator
        out
    }

    #[test]
    fn list_vpk_entries_reads_extension_path_and_name() {
        let mut tree = Vec::new();
        tree.extend_from_slice(b"txt\0");
        tree.extend_from_slice(b" \0"); // корінь
        tree.extend_from_slice(b"readme\0");
        tree.extend_from_slice(&build_vpk_tree_entry(100));
        tree.push(0); // кінець списку імен для цього шляху
        tree.push(0); // кінець списку шляхів для цього розширення
        tree.push(0); // кінець списку розширень

        let core = build_minimal_vpk(&tree, &[]);
        let entries = list_archive_entries("VPK", &core).expect("vpk must list entries");
        assert_eq!(entry_names(&entries), vec!["readme.txt"]);
        assert_eq!(entries[0].size, 100);
    }

    fn build_rar_file_head(name: &str, unp_size: u32) -> Vec<u8> {
        let mut file_specific = Vec::new();
        file_specific.extend_from_slice(&0u32.to_le_bytes()); // PACK_SIZE
        file_specific.extend_from_slice(&unp_size.to_le_bytes()); // UNP_SIZE
        file_specific.push(0); // HOST_OS
        file_specific.extend_from_slice(&0u32.to_le_bytes()); // FILE_CRC
        file_specific.extend_from_slice(&0u32.to_le_bytes()); // FTIME
        file_specific.push(0); // UNP_VER
        file_specific.push(0); // METHOD
        file_specific.extend_from_slice(&(name.len() as u16).to_le_bytes()); // NAME_SIZE
        file_specific.extend_from_slice(&0u32.to_le_bytes()); // ATTR
        file_specific.extend_from_slice(name.as_bytes());

        let head_size = (7 + file_specific.len()) as u16;
        let mut out = vec![0u8, 0u8, 0x74]; // HEAD_CRC(2) + HEAD_TYPE: FILE_HEAD
        out.extend_from_slice(&0u16.to_le_bytes()); // HEAD_FLAGS: без LONG_BLOCK/LHD_LARGE
        out.extend_from_slice(&head_size.to_le_bytes());
        out.extend_from_slice(&file_specific);
        out
    }

    #[test]
    fn list_rar_entries_reads_name_and_unpacked_size() {
        let mut core = b"Rar!\x1a\x07\x00".to_vec();
        core.extend_from_slice(&build_rar_file_head("test.txt", 12345));
        core.extend_from_slice(&build_rar_file_head("second.bin", 999));

        let entries = list_archive_entries("RAR", &core).expect("rar must list entries");
        assert_eq!(entry_names(&entries), vec!["test.txt", "second.bin"]);
        assert_eq!(entries[0].size, 12345);
        assert_eq!(entries[1].size, 999);
    }

    #[test]
    fn gltf_facts_reads_scene_counts_from_json_chunk() {
        let json = serde_json::json!({
            "asset": {"generator": "TestExporter 1.0"},
            "scenes": [{}],
            "nodes": [{}, {}, {}],
            "meshes": [{}],
            "materials": [{}, {}],
        });
        let json_bytes = serde_json::to_vec(&json).unwrap();

        let mut core = b"glTF".to_vec();
        core.extend_from_slice(&2u32.to_le_bytes()); // version
        let total_len = 12 + 8 + json_bytes.len();
        core.extend_from_slice(&(total_len as u32).to_le_bytes());
        core.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
        core.extend_from_slice(b"JSON");
        core.extend_from_slice(&json_bytes);

        let facts = format_facts("glTF-Binary", &core).expect("gltf must produce facts");
        assert!(facts.contains("Сцени: 1"), "{facts}");
        assert!(facts.contains("Вузли: 3"), "{facts}");
        assert!(facts.contains("Меші: 1"), "{facts}");
        assert!(facts.contains("Матеріали: 2"), "{facts}");
        assert!(facts.contains("Створено: TestExporter 1.0"), "{facts}");
    }

    #[test]
    fn ply_facts_reads_format_and_elements() {
        let core = b"ply\nformat ascii 1.0\nelement vertex 1234\nproperty float x\nelement face 567\nproperty list uchar int vertex_indices\nend_header\n".to_vec();
        let facts = format_facts("PLY", &core).expect("ply must produce facts");
        assert!(facts.contains("Формат: ascii"), "{facts}");
        assert!(facts.contains("vertex: 1234"), "{facts}");
        assert!(facts.contains("face: 567"), "{facts}");
    }
}
