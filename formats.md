# Supported formats

`greatie` recognizes files embedded in an arbitrary binary stream using a database of **200 magic signatures**, ported from the `file(1)`/`libmagic` database (see `SPEC.md`). This file is the full reference of every supported format; the same list (without the extension and boundary-detection columns) is available directly from the app via `greatie --formats`, or the `?`/`h` key in the TUI.

## How finding boundaries are determined

Each format uses one of three ways to determine the end of an embedded fragment (see section 5 of `SPEC.md` for details):

- **Structural validator** (106 format(s)) — the file is fully parsed (ZIP/EOCD headers, PNG chunks, ELF/PE sections, etc.), so the boundary is exact and the confidence score is higher.
- **End marker — heuristic** (3) — the boundary is found via a known end-of-format byte marker (e.g. `IEND` for PNG, `FFD9` for JPEG), without fully parsing the structure.
- **Heuristic with no marker** (91) — the boundary is set at the start of the next finding, or at end of file; the lowest confidence.

Additionally, 8 format(s) (TAR/CPIO/ar/WAD/PAK, etc.) can extract the embedded file/entry name directly from their internal structure — shown alongside the finding in `scan`/the TUI.

## Images

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| PNG | `.png` | Structural validator (exact boundary) | Lossless raster image (DEFLATE); the de-facto web standard, also used for OS icons and in image editors (PNG Group, 1996). |
| JPEG | `.jpg` | Structural validator (exact boundary) | Lossy raster photo (DCT compression); the primary format for digital photography and web images (ISO/ITU, 1992). |
| GIF87a | `.gif` | End marker (heuristic) | Raster image with a palette of up to 256 colors; 89a adds animation. A web classic, still used for short animations (CompuServe). |
| GIF89a | `.gif` | End marker (heuristic) | Raster image with a palette of up to 256 colors; 89a adds animation. A web classic, still used for short animations (CompuServe). |
| BMP | `.bmp` | Heuristic — up to the next finding | Windows raster image (uncompressed or RLE); an intermediate format in Windows GDI and older software (Microsoft). |
| RDIB | `.rdi` | Structural validator (exact boundary) | Windows raster image (uncompressed or RLE); an intermediate format in Windows GDI and older software (Microsoft). |
| ICO | `.ico` | Structural validator (exact boundary) | Windows icon format: several sizes/color depths in one file (Microsoft). |
| CUR | `.cur` | Structural validator (exact boundary) | Windows cursor format (ANI is animated); used by Explorer and applications (Microsoft). |
| ANI | `.ani` | Structural validator (exact boundary) | Windows cursor format (ANI is animated); used by Explorer and applications (Microsoft). |
| ICNS | `.icns` | Structural validator (exact boundary) | macOS icon format with multiple resolutions; used by Finder and applications (Apple). |
| WEBP | `.webp` | Structural validator (exact boundary) | Google's modern web image format (lossy and lossless), smaller than PNG/JPEG at comparable quality (Google, 2010). |
| TIFF-LE | `.tiff` | Heuristic — up to the next finding | Flexible raster image container with layer and metadata support; widely used in print and scanning (Aldus/Adobe). |
| TIFF-BE | `.tiff` | Heuristic — up to the next finding | Flexible raster image container with layer and metadata support; widely used in print and scanning (Aldus/Adobe). |
| PSD | `.psd` | Heuristic — up to the next finding | Adobe Photoshop's native format, preserving layers, masks, and styles (Adobe). |
| HEIC | `.heic` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| HEIC-10bit | `.heic` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| HEIF-mif1 | `.heif` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| HEIF-msf1 | `.heif` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| HEIF-heis | `.heic` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| HEIF-hevc | `.heic` | Structural validator (exact boundary) | Image format based on the HEVC codec; the primary photo format on iOS/macOS (Apple, MPEG standard). |
| AVIF | `.avif` | Structural validator (exact boundary) | Image format based on the AV1 codec; a modern alternative to WebP/JPEG on the web (Alliance for Open Media). |
| AVIF-sequence | `.avif` | Structural validator (exact boundary) | Image format based on the AV1 codec; a modern alternative to WebP/JPEG on the web (Alliance for Open Media). |
| JP2 | `.jp2` | Structural validator (exact boundary) | JPEG 2000 — a raster format with wavelet compression; used in film archiving (DCP) and medical imaging (ISO/ITU). |
| JXL | `.jxl` | Structural validator (exact boundary) | JPEG XL — a new image format with better compression than JPEG, intended to replace JPEG/PNG/GIF on the web (ISO/IEC). |
| XCF | `.xcf` | Heuristic — up to the next finding | GIMP's native editor format, preserving layers (GNU Project). |
| PSP | `.psp` | Heuristic — up to the next finding | Paint Shop Pro's native editor format (Corel/Jasc). |
| XPM | `.xpm` | Heuristic — up to the next finding | X Window System raster format — an image written as a C-language array (X.Org). |
| DDS | `.dds` | Heuristic — up to the next finding | DirectDraw Surface — a compressed texture format (DXT/BC) for DirectX and games (Microsoft). |
| EXR | `.exr` | Heuristic — up to the next finding | OpenEXR — a high dynamic range (HDR) image format for film production and VFX (Industrial Light & Magic). |
| JBIG2 | `.jb2` | Heuristic — up to the next finding | Compression for black-and-white (bilevel) scanned images; most often found embedded in PDF (ITU-T). |
| PPM | `.ppm` | Heuristic — up to the next finding | The simplest text/binary raster format from Netpbm, for exchange between Unix utilities. |
| PGM | `.pgm` | Heuristic — up to the next finding | The simplest text/binary raster format from Netpbm, for exchange between Unix utilities. |
| PBM | `.pbm` | Heuristic — up to the next finding | The simplest text/binary raster format from Netpbm, for exchange between Unix utilities. |
| FLIF | `.flif` | Heuristic — up to the next finding | Free Lossless Image Format — an experimental lossless format whose ideas were partly inherited by JPEG XL. |
| SVG | `.svg` | Heuristic — up to the next finding | XML-based vector image; the web standard for scalable icons, logos, and illustrations (W3C). |
| EPS | `.eps` | Heuristic — up to the next finding | Encapsulated PostScript — a vector format for print and for embedding illustrations in documents (Adobe). |
| EPS-Binary | `.eps` | Structural validator (exact boundary) | Encapsulated PostScript — a vector format for print and for embedding illustrations in documents (Adobe). |
| WMF | `.wmf` | Structural validator (exact boundary) | Windows metafile (a sequence of GDI commands); used to embed vector graphics in Office documents (Microsoft). |
| WMF-Placeable | `.wmf` | Structural validator (exact boundary) | Windows metafile (a sequence of GDI commands); used to embed vector graphics in Office documents (Microsoft). |
| EMF | `.emf` | Structural validator (exact boundary) | Windows metafile (a sequence of GDI commands); used to embed vector graphics in Office documents (Microsoft). |
| MNG | `.mng` | Structural validator (exact boundary) | An animated extension of the PNG format; effectively obsolete. |
| JNG | `.jng` | Structural validator (exact boundary) | An animated extension of the PNG format; effectively obsolete. |
| PICT | `.pict` | Heuristic — up to the next finding | The vector/raster QuickDraw format of classic Mac OS — the image-exchange standard on System 6-9 (Apple). |
| XFig | `.fig` | Heuristic — up to the next finding | Vector diagram format of the Xfig editor for the X Window System. |
| QOI | `.qoi` | Heuristic — up to the next finding | "Quite OK Image" — a simple, fast lossless image compression format, an alternative to PNG for tooling. |
| HDR | `.hdr` | Heuristic — up to the next finding | The Radiance format for high dynamic range (HDR) images, used in 3D rendering. |
| PVR | `.pvr` | Heuristic — up to the next finding | PowerVR texture format for GPUs (Imagination Technologies), common in mobile games. |
| CDR | `.cdr` | Structural validator (exact boundary) | CorelDRAW's native vector format. |

## Executables & bytecode

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| ELF | `.elf` | Structural validator (exact boundary) | Executables, libraries, and object files on Linux/Unix (Executable and Linkable Format). |
| PE | `.exe` | Structural validator (exact boundary) | Windows executables and DLLs (Portable Executable, Microsoft). |
| Mach-O-32-BE | `.macho` | Structural validator (exact boundary) | macOS/iOS executables, including universal "fat" binaries containing multiple architectures (Apple). |
| Mach-O-32-LE | `.macho` | Structural validator (exact boundary) | macOS/iOS executables, including universal "fat" binaries containing multiple architectures (Apple). |
| Mach-O-64-BE | `.macho` | Structural validator (exact boundary) | macOS/iOS executables, including universal "fat" binaries containing multiple architectures (Apple). |
| Mach-O-64-LE | `.macho` | Structural validator (exact boundary) | macOS/iOS executables, including universal "fat" binaries containing multiple architectures (Apple). |
| Mach-O-Fat | `.macho` | Structural validator (exact boundary) | macOS/iOS executables, including universal "fat" binaries containing multiple architectures (Apple). |
| PEF | `.pef` | Structural validator (exact boundary) | Preferred Executable Format — classic Mac OS executables for PowerPC (Apple). |
| Amiga-Hunk | `.amiga` | Heuristic — up to the next finding | AmigaOS executable format (Commodore/Amiga). |
| XCOFF32 | `.xcoff` | Heuristic — up to the next finding | AIX executable format (IBM). |
| XCOFF64 | `.xcoff` | Heuristic — up to the next finding | AIX executable format (IBM). |
| Atari-ST | `.prg` | Heuristic — up to the next finding | Atari ST executable format (GEMDOS). |
| Java-Class | `.class` | Heuristic — up to the next finding | Compiled Java class bytecode (Oracle/Sun). |
| DEX | `.dex` | Structural validator (exact boundary) | Dalvik/ART bytecode for Android applications (Google). |
| LNK | `.lnk` | Heuristic — up to the next finding | Windows shortcut: a link to a file/program with stored target metadata (Microsoft). |

## Archives & compression

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| ZIP | `.zip` | Structural validator (exact boundary) | A general-purpose archive (DEFLATE); the basis of DOCX/XLSX/JAR/APK and many game containers (PKWARE). |
| GZIP | `.gz` | Structural validator (exact boundary) | Single-stream data compression (DEFLATE); typically used for .tar.gz and web Content-Encoding (GNU). |
| BZIP2 | `.bz2` | Heuristic — up to the next finding | Compression based on the Burrows-Wheeler transform — a higher compression ratio than gzip at the cost of more CPU load. |
| TAR | `.tar` | Structural validator (exact boundary) | A Unix archive that simply concatenates files with headers (no compression), usually paired with gzip/bzip2/xz. |
| 7Z | `.7z` | Structural validator (exact boundary) | A 7-Zip archive with a high compression ratio using the LZMA algorithm, popular on Windows (Igor Pavlov). |
| RAR | `.rar` | Structural validator (exact boundary) | A proprietary WinRAR archive with damage-recovery and multi-volume splitting support (RARLAB). |
| CPIO-newc | `.cpio` | Structural validator (exact boundary) | The Unix cpio archive format; the newc variant is used in the Linux kernel's initramfs. |
| CPIO-crc | `.cpio` | Structural validator (exact boundary) | The Unix cpio archive format; the newc variant is used in the Linux kernel's initramfs. |
| CPIO-odc | `.cpio` | Structural validator (exact boundary) | The Unix cpio archive format; the newc variant is used in the Linux kernel's initramfs. |
| AR | `.a` | Structural validator (exact boundary) | Unix static-library archive (.a) and .deb packages (GNU Binutils). |
| XAR | `.xar` | Heuristic — up to the next finding | Extensible Archive — the container used by macOS .pkg installers (Apple). |
| ISO9660 | `.iso` | Structural validator (exact boundary) | Optical-disc (CD/DVD) filesystem image (ISO). |
| ZSTD | `.zst` | Structural validator (exact boundary) | A modern, fast compression algorithm (Facebook/Meta), used in build systems and backups. |
| LZ4 | `.lz4` | Heuristic — up to the next finding | An extremely fast compression algorithm with a modest compression ratio — used where speed is critical (games, databases). |
| XZ | `.xz` | Heuristic — up to the next finding | An LZMA2 compression container with a high compression ratio, typically .tar.xz on Linux distributions. |
| LZO | `.lzo` | Heuristic — up to the next finding | A very fast compression algorithm, used in Linux kernel bootloaders and embedded systems. |
| MPQ | `.mpq` | Structural validator (exact boundary) | A resource archive used by Blizzard games (Warcraft III, Diablo II, World of Warcraft). |
| SquashFS | `.squashfs` | Structural validator (exact boundary) | A compressed, read-only filesystem, typically used for initramfs and Linux live distributions. |
| CAB | `.cab` | Structural validator (exact boundary) | A Microsoft Cabinet archive, used by Windows installers. |
| StuffIt | `.sit` | Heuristic — up to the next finding | A StuffIt archive — historically the main compression format on classic Mac OS. |
| ARJ | `.arj` | Heuristic — up to the next finding | The ARJ archive format, popular on DOS and BBSes in the 1990s. |

## Fonts

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| TTF | `.ttf` | Structural validator (exact boundary) | A TrueType/OpenType font (TTC is a font collection); the font standard in OSes and on the web (Apple/Microsoft, Adobe for OTF). |
| OTF | `.otf` | Structural validator (exact boundary) | A TrueType/OpenType font (TTC is a font collection); the font standard in OSes and on the web (Apple/Microsoft, Adobe for OTF). |
| TTC | `.ttc` | Heuristic — up to the next finding | A TrueType/OpenType font (TTC is a font collection); the font standard in OSes and on the web (Apple/Microsoft, Adobe for OTF). |
| WOFF | `.woff` | Structural validator (exact boundary) | Web font format (a compressed wrapper around TTF/OTF) for CSS @font-face (W3C). |
| WOFF2 | `.woff2` | Structural validator (exact boundary) | Web font format (a compressed wrapper around TTF/OTF) for CSS @font-face (W3C). |
| BDF | `.bdf` | Heuristic — up to the next finding | A bitmap font format for the X Window System (Adobe/X.Org). |

## 3D models & CAD

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| glTF-Binary | `.glb` | Structural validator (exact boundary) | A compact binary 3D format for the web and real-time use — the "JPEG of 3D" (Khronos Group). |
| FBX | `.fbx` | Heuristic — up to the next finding | A format for exchanging 3D scenes and animation between packages (Autodesk). |
| PLY | `.ply` | Heuristic — up to the next finding | A polygon mesh format for storing 3D meshes obtained from scanners (Stanford). |
| KTX | `.ktx` | Heuristic — up to the next finding | A GPU texture container for OpenGL/Vulkan (Khronos Group). |
| KTX2 | `.ktx2` | Heuristic — up to the next finding | A GPU texture container for OpenGL/Vulkan (Khronos Group). |
| DWG | `.dwg` | Heuristic — up to the next finding | AutoCAD's native drawing format (Autodesk). |

## Audio

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| MP3 | `.mp3` | Heuristic — up to the next finding | Lossy compressed audio (MPEG-1 Layer III) — the most widespread audio format (Fraunhofer/ISO). |
| M4A | `.m4a` | Structural validator (exact boundary) | An MPEG-4 container for audio (AAC or ALAC), typically used in Apple Music/iTunes. |
| M4B | `.m4b` | Structural validator (exact boundary) | An MPEG-4 container for audio (AAC or ALAC), typically used in Apple Music/iTunes. |
| M4P | `.m4p` | Structural validator (exact boundary) | An MPEG-4 container for audio (AAC or ALAC), typically used in Apple Music/iTunes. |
| OGG | `.ogg` | Structural validator (exact boundary) | An open Xiph.Org media container, most often used for the Vorbis codec. |
| ASF | `.wma` | Structural validator (exact boundary) | Microsoft's Advanced Systems Format — a WMV/WMA container, a predecessor of modern media containers. |
| WAV | `.wav` | Structural validator (exact boundary) | Uncompressed (PCM) or encoded audio in a RIFF container (Microsoft/IBM). |
| AIFF | `.aiff` | Structural validator (exact boundary) | Apple's audio format (uncompressed or compressed) — the WAV counterpart on classic Mac OS. |
| AIFC | `.aifc` | Structural validator (exact boundary) | Apple's audio format (uncompressed or compressed) — the WAV counterpart on classic Mac OS. |
| 8SVX | `.8svx` | Structural validator (exact boundary) | An 8-bit Amiga sound format (IFF 8SVX). |
| FLAC | `.flac` | Heuristic — up to the next finding | Lossless audio compression, popular for music archiving. |
| APE | `.ape` | Heuristic — up to the next finding | Monkey's Audio — lossless audio compression with a high compression ratio. |
| WavPack | `.wv` | Heuristic — up to the next finding | An open-source lossless (and hybrid) audio compression format. |
| TTA | `.tta` | Heuristic — up to the next finding | True Audio — a lossless audio compression format. |
| DSF | `.dsf` | Structural validator (exact boundary) | A streaming DSD (Direct Stream Digital) format for audiophile recordings (Sony/Philips, the SACD standard). |
| CAF | `.caf` | Structural validator (exact boundary) | Apple's Core Audio Format — a container for various audio codecs on macOS/iOS. |
| MIDI | `.mid` | Structural validator (exact boundary) | Not audio, but a sequence of musical commands (notes, instruments) for synthesizers; RMID is the same MIDI wrapped in a RIFF container. |
| RMID | `.rmi` | Structural validator (exact boundary) | Not audio, but a sequence of musical commands (notes, instruments) for synthesizers; RMID is the same MIDI wrapped in a RIFF container. |
| MOD-MK | `.mod` | Structural validator (exact boundary) | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| MOD-FLT4 | `.mod` | Structural validator (exact boundary) | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| MOD-6CHN | `.mod` | Heuristic — up to the next finding | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| MOD-8CHN | `.mod` | Heuristic — up to the next finding | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| XM | `.xm` | Heuristic — up to the next finding | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| S3M | `.s3m` | Heuristic — up to the next finding | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| IT | `.it` | Heuristic — up to the next finding | A tracker music module (samples and score in one file) — popular on the Amiga and in the demoscene. |
| AU | `.au` | Structural validator (exact boundary) | A simple Sun/NeXT audio format. |
| VOC | `.voc` | Structural validator (exact boundary) | Creative Labs (Sound Blaster) sound file format. |

## Video & multimedia containers

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| MP4-isom | `.mp4` | Structural validator (exact boundary) | An MPEG-4 container for video/audio; the primary format for streaming, cameras, and smartphones. |
| MP4-mp42 | `.mp4` | Structural validator (exact boundary) | An MPEG-4 container for video/audio; the primary format for streaming, cameras, and smartphones. |
| MP4-mp41 | `.mp4` | Structural validator (exact boundary) | An MPEG-4 container for video/audio; the primary format for streaming, cameras, and smartphones. |
| MP4-avc1 | `.mp4` | Structural validator (exact boundary) | An MPEG-4 container for video/audio; the primary format for streaming, cameras, and smartphones. |
| MP4-iso2 | `.mp4` | Structural validator (exact boundary) | An MPEG-4 container for video/audio; the primary format for streaming, cameras, and smartphones. |
| MOV | `.mov` | Structural validator (exact boundary) | Apple's QuickTime container — the historical basis of the MP4 format. |
| 3GP | `.3gp` | Structural validator (exact boundary) | An MPEG-4 container for mobile phones (3GPP standard). |
| 3G2 | `.3g2` | Structural validator (exact boundary) | An MPEG-4 container for mobile phones (3GPP standard). |
| 3GP-3gp5 | `.3gp` | Structural validator (exact boundary) | An MPEG-4 container for mobile phones (3GPP standard). |
| AVI | `.avi` | Structural validator (exact boundary) | Windows Audio Video Interleave container (Microsoft). |
| EBML | `.mkv` | Structural validator (exact boundary) | A binary markup format underlying the Matroska (MKV) and WebM containers. |
| FLV | `.flv` | Structural validator (exact boundary) | The Flash Video container — historically used by Adobe Flash Player and YouTube. |
| MPEG-PS | `.mpg` | Heuristic — up to the next finding | Program Stream/Elementary Stream MPEG-1/2 — used on DVD-Video. |
| MPEG-ES | `.m2v` | Heuristic — up to the next finding | Program Stream/Elementary Stream MPEG-1/2 — used on DVD-Video. |
| M4V | `.m4v` | Structural validator (exact boundary) | An MPEG-4 container for video from Apple (protected iTunes video / Apple video players). |
| SWF-uncompressed | `.swf` | Structural validator (exact boundary) | The Adobe/Macromedia Flash format; dominated web animation and browser games in the 2000s until Flash's decline. |
| SWF-zlib | `.swf` | Structural validator (exact boundary) | The Adobe/Macromedia Flash format; dominated web animation and browser games in the 2000s until Flash's decline. |
| SWF-lzma | `.swf` | Structural validator (exact boundary) | The Adobe/Macromedia Flash format; dominated web animation and browser games in the 2000s until Flash's decline. |
| Shockwave-Director | `.dcr` | Structural validator (exact boundary) | An Adobe/Macromedia Director file (Shockwave projector) — interactive multimedia from the 1990s-2000s. |
| RealMedia | `.rm` | Structural validator (exact boundary) | A RealAudio/RealVideo container (RealNetworks), popular for streaming in the 1990s-2000s. |

## Virtual disk images

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| VMDK | `.vmdk` | Heuristic — up to the next finding | VMware virtual disk format. |
| VHDX | `.vhdx` | Heuristic — up to the next finding | Hyper-V virtual disk format (Microsoft). |
| QCOW2 | `.qcow2` | Heuristic — up to the next finding | QEMU/KVM virtual disk format with snapshot support (copy-on-write). |
| VDI | `.vdi` | Heuristic — up to the next finding | VirtualBox virtual disk format (Oracle). |

## Documents & structured/scientific data

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| PDF | `.pdf` | End marker (heuristic) | A fixed-layout document format for printing and exchange (Adobe, ISO 32000 standard). |
| RPM | `.rpm` | Heuristic — up to the next finding | An RPM package manager package (Red Hat, Fedora, openSUSE). |
| REG4 | `.reg` | Heuristic — up to the next finding | A Windows registry export file (text, various format versions) (Microsoft). |
| REG5 | `.reg` | Heuristic — up to the next finding | A Windows registry export file (text, various format versions) (Microsoft). |
| BPLIST | `.plist` | Heuristic — up to the next finding | Binary property list — a configuration/data-serialization format on macOS/iOS (Apple). |
| HDF5 | `.h5` | Heuristic — up to the next finding | A hierarchical scientific-data format, used in physics and machine learning (e.g. Keras models) (HDF Group). |
| NetCDF | `.nc` | Heuristic — up to the next finding | A multidimensional scientific-data format, common in meteorology and oceanography (Unidata). |
| MAT | `.mat` | Heuristic — up to the next finding | MATLAB data file format (MathWorks). |
| NPY | `.npy` | Heuristic — up to the next finding | The array-serialization format of the NumPy library (Python). |
| Parquet | `.parquet` | Heuristic — up to the next finding | A columnar data-storage format for large analytical workloads (Apache). |
| Avro | `.avro` | Heuristic — up to the next finding | A schema-based data-serialization format, typical for Kafka and Hadoop (Apache). |
| ORC | `.orc` | Heuristic — up to the next finding | A columnar data-storage format optimized for Hive/Hadoop (Apache). |
| WebVTT | `.vtt` | Heuristic — up to the next finding | A subtitle format for the HTML5 <video> tag (W3C). |
| ASS | `.ass` | Heuristic — up to the next finding | The Advanced SubStation Alpha subtitle format with text styling, popular in anime fansubs. |
| PGP-Message | `.pgp` | Heuristic — up to the next finding | OpenPGP data: an encrypted message, key, or signature (RFC 4880) — used to encrypt and sign mail/files. |
| PGP-PublicKey | `.asc` | Heuristic — up to the next finding | OpenPGP data: an encrypted message, key, or signature (RFC 4880) — used to encrypt and sign mail/files. |
| PGP-PrivateKey | `.asc` | Heuristic — up to the next finding | OpenPGP data: an encrypted message, key, or signature (RFC 4880) — used to encrypt and sign mail/files. |
| PGP-Signature | `.sig` | Heuristic — up to the next finding | OpenPGP data: an encrypted message, key, or signature (RFC 4880) — used to encrypt and sign mail/files. |
| PEM | `.pem` | Heuristic — up to the next finding | Text (Base64) encoding of cryptographic objects — certificates and keys (RFC 7468). |
| MBOX | `.mbox` | Heuristic — up to the next finding | A mailbox storage format as a single file of concatenated messages (Unix mail). |
| PST | `.pst` | Heuristic — up to the next finding | A Microsoft Outlook mailbox/archive file. |
| DjVu | `.djvu` | Heuristic — up to the next finding | A high-compression scanned-document format — a PDF alternative for books and magazines (LizardTech). |
| CRX | `.crx` | Heuristic — up to the next finding | A Google Chrome browser extension package. |
| Torrent | `.torrent` | Heuristic — up to the next finding | A BitTorrent metadata file (a list of files and piece hashes) for P2P downloads. |
| JKS | `.jks` | Heuristic — up to the next finding | Java KeyStore — a container for Java cryptographic keys and certificates. |
| MOBI | `.mobi` | Heuristic — up to the next finding | The Amazon Kindle e-book format (Mobipocket). |
| JetDB | `.mdb` | Heuristic — up to the next finding | The Microsoft Access/Jet database file format (.mdb). |
| AceDB | `.accdb` | Heuristic — up to the next finding | The database file format of the ACeDB scientific software, used in genetics and bioinformatics. |
| SPSS | `.sav` | Heuristic — up to the next finding | The data file format of the IBM SPSS statistics package. |
| FDF | `.fdf` | Heuristic — up to the next finding | Forms Data Format — PDF form data (Adobe). |
| ICC | `.icc` | Structural validator (exact boundary) | A color-management profile: describes a device's (monitor, printer, camera) color space for accurate color reproduction (ICC/ISO 15076). |
| DPX-BE | `.dpx` | Structural validator (exact boundary) | Digital Picture Exchange — a frame format for film production: editing and film archiving (SMPTE standard). |
| DPX-LE | `.dpx` | Structural validator (exact boundary) | Digital Picture Exchange — a frame format for film production: editing and film archiving (SMPTE standard). |

## Databases & document containers

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| SQLite | `.sqlite` | Structural validator (exact boundary) | An embedded relational database file (SQLite) — used in mobile and desktop applications. |
| Blender | `.blend` | Structural validator (exact boundary) | The native project file format of the Blender 3D editor. |
| AppleSingle | `.as` | Structural validator (exact boundary) | An encoding of classic Mac OS resource forks and metadata into one/two files on non-HFS filesystems (Apple). |
| AppleDouble | `.adf` | Structural validator (exact boundary) | An encoding of classic Mac OS resource forks and metadata into one/two files on non-HFS filesystems (Apple). |
| OLE2 | `.doc` | Heuristic — up to the next finding | Composite Document File — the container for legacy Microsoft Office formats (.doc/.xls/.ppt before 2007). |
| CHM | `.chm` | Heuristic — up to the next finding | Compiled HTML Help — Windows help files (Microsoft). |
| ILBM | `.ilbm` | Structural validator (exact boundary) | An Amiga raster/animation format based on IFF (InterLeaved BitMap). |
| ANIM | `.anim` | Structural validator (exact boundary) | An Amiga raster/animation format based on IFF (InterLeaved BitMap). |
| ANBM | `.anbm` | Structural validator (exact boundary) | An Amiga raster/animation format based on IFF (InterLeaved BitMap). |
| RIFF-PAL | `.pal` | Structural validator (exact boundary) | A color palette in a RIFF container (Microsoft). |

## Game engine & game-data formats

| Format | Extension | Boundary detection | Description |
|---|---|---|---|
| WAD-I | `.wad` | Structural validator (exact boundary) | A game resource format used by the Doom / id Tech engine (id Software). |
| WAD-P | `.wad` | Structural validator (exact boundary) | A game resource format used by the Doom / id Tech engine (id Software). |
| PAK-Quake | `.pak` | Structural validator (exact boundary) | A resource archive for the game Quake (id Software). |
| VBSP | `.bsp` | Structural validator (exact boundary) | A compiled Source engine level map (Half-Life 2, Counter-Strike, Portal, TF2 — Valve). |
| VPK | `.vpk` | Structural validator (exact boundary) | A Source engine resource archive (Valve). |
| NES | `.nes` | Structural validator (exact boundary) | The iNES ROM image format for the Nintendo NES/Famicom. |
| Genesis | `.bin` | Heuristic — up to the next finding | A Sega Genesis/Mega Drive ROM cartridge header. |
| UnityFS | `.unity3d` | Structural validator (exact boundary) | The asset bundle format of the Unity engine (Unity Technologies). |
| Godot-PCK | `.pck` | Heuristic — up to the next finding | A resource archive for the Godot Engine. |
| RPA | `.rpa` | Heuristic — up to the next finding | A resource archive for the Ren'Py visual-novel engine. |

