---
name: disk-forensics
description: "Analyze disk images, file systems, and memory captures for digital evidence recovery in forensic investigations and CTF challenges. Use when the user mentions 'disk forensics,' 'forensic analysis,' 'disk image,' 'file carving,' 'deleted files,' 'evidence recovery,' 'timeline analysis,' 'memory forensics,' 'volatility,' 'autopsy,' 'sleuthkit,' 'plaso,' 'log2timeline,' 'artifact analysis,' 'chain of custody,' or needs to examine a forensic image."
allowed-tools: Bash, Read, Write, Grep, Glob
---

# Disk Forensics — Digital Evidence Analysis

Analyze disk images and file systems to recover evidence, reconstruct timelines, and identify artifacts.

Cross-references: `incident-triage` for the upstream containment phase that captures the image this skill analyzes — that skill makes the bit-for-bit copy; this skill analyzes it. `breach-patterns` for translating the forensic findings into preemptive controls so the same root cause doesn't recur.

## Authorization Check

Before analyzing any image, confirm:
1. **Lawful basis** — the user has authorization for this analysis (internal investigation with documented scope, court-ordered work, signed IR engagement, your own system, CTF / lab environment)
2. **Chain of custody is preserved** — the image and its hashes were captured in a way that survives evidentiary scrutiny, OR the scope is explicitly non-evidentiary (CTF, internal triage where chain-of-custody is not the goal)
3. **Privacy scope** — the analysis stays within what was authorized; personal data outside the scope is not pulled, analyzed, or reported

If lawful basis is unclear, ask before proceeding. Never analyze an image you cannot confirm the user is authorized to possess.

## Evidence Handling Principles

- Always work on copies, never originals
- Verify image integrity with hash comparison before analysis
- Mount everything read-only
- Document every command and finding
- Preserve timestamps — never modify source evidence

## Methodology

### Step 1: Image Identification and Integrity

Identify the image format and verify integrity:

```bash
file <image>                    # Identify format (E01, dd/raw, VMDK, VHD)
sha256sum <image>               # Compare to provided hash
```

For E01 images, use `ewfinfo` to extract metadata.

### Step 2: Partition Layout

Examine the partition structure:

```bash
fdisk -l <image>                # Partition table
mmls <image>                    # Sleuth Kit partition layout
```

Calculate mount offsets: `sector_start × sector_size`

### Step 3: Mount and Explore

Mount read-only and survey the file system:

```bash
mount -o ro,loop,offset=<bytes> <image> /mnt/evidence
ls -laR /mnt/evidence
```

For encrypted volumes, identify the encryption type and request the key/passphrase.

### Step 4: File System Analysis (Sleuth Kit)

```bash
fsstat -o <offset> <image>              # File system details
fls -r -o <offset> <image>             # Full file listing (deleted files marked with *)
icat -o <offset> <image> <inode>       # Extract specific file by inode
```

### Step 5: Artifact Recovery

**Deleted files:** Use `fls` to find (marked with `*`), `icat` to extract by inode.

**File carving:** Run `foremost` or `scalpel` on unallocated space to recover files by header signatures.

**Hidden data:**
- NTFS alternate data streams
- HFS+ resource forks
- Check image files for steganography: `exiftool`, `binwalk`, `steghide`

**System artifacts:**
- Browser history: `~/.mozilla`, `~/Library/Safari`, `AppData\Local\Google`
- System logs: `/var/log/*`, Windows Event Logs
- Registry hives (Windows): SAM, SYSTEM, SOFTWARE, NTUSER.DAT
- Recently accessed files, USB device history, prefetch files

### Step 6: Metadata and Timestamps

```bash
exiftool <file>                 # EXIF, XMP, IPTC metadata
stat <file>                     # MAC times (Modified, Accessed, Changed)
```

For NTFS: examine `$MFT` timestamps and `$UsnJrnl` for change journal entries.

Use `mactime` (Sleuth Kit) to generate a unified timeline from body files.

### Step 7: Keyword Search

```bash
strings <image> | grep -i <keyword>    # Raw string search across image
```

Use `bulk_extractor` for automated extraction of emails, URLs, credit card numbers, and other structured data.

### Step 8: Timeline Construction

Collect all timestamps into a unified timeline. Cross-reference file events with log entries. Flag anomalies:
- Timestamps before the OS install date
- Future-dated files
- Gaps in otherwise continuous log sequences
- Timestamps inconsistent with timezone settings

## Output Format

```markdown
# Forensic Analysis Report
## Case: [identifier]
## Image: [filename] — SHA256: [hash]
## Date of Analysis: [date]

### Image Integrity
- Hash verified: [yes/no]
- Algorithm: [SHA256]

### Partition Layout
| # | Type | Start | Size | File System |
|---|------|-------|------|-------------|

### Key Findings
#### Finding 1: [Title]
- **Evidence:** [file path or artifact]
- **Content:** [description]
- **Timestamp:** [UTC]
- **Significance:** [why this matters]

### Recovered Files
| File | Source | Recovery Method | SHA256 | Significance |
|------|--------|-----------------|--------|-------------|

### Timeline
| Timestamp (UTC) | Event | Source | Notes |
|-----------------|-------|--------|-------|

### Conclusions
[Summary of findings and their implications]
```

## Boundaries

- Work only on provided images and files
- Maintain read-only access at all times
- Document chain of custody for real investigations
- For CTF challenges, focus on finding flags and solving the challenge
- Never modify evidence or suggest evidence tampering
- Refuse requests involving unauthorized device access

## References

- NIST SP 800-86: Guide to Integrating Forensic Techniques
- The Sleuth Kit documentation
- SANS Digital Forensics cheat sheets
