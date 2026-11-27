"""photo_scan.py - recover the hidden manifesto from evidence.png.

The image was encoded with Stepic-style LSB steganography (the method from Lab 8):
  * 3 pixels = 9 colour-channel values = 1 hidden byte
  * the first 8 channel LSBs hold the byte, most significant bit first
  * the 9th channel LSB is a stop flag: 0 = more bytes follow, 1 = this was the last byte

The decoder below implements that scheme directly, so Pillow is the only dependency.
cross_check_with_stepic() can confirm the result against the real stepic library from Lab 8.

The original image is only ever opened for reading, and its SHA-256 is compared before and
after extraction to prove it was not modified.
"""
import hashlib
import sys
from pathlib import Path

from PIL import Image, UnidentifiedImageError

SIGNATURE = b"The Architect"        # the author's signature marks the end of the manifesto
MAX_MESSAGE_BYTES = 64 * 1024       # longer than this is not a plausible manifesto; also bounds work
MIN_PRINTABLE_RATIO = 0.98          # share of decoded characters that must be normal text


class PhotoScanError(Exception):
    """Base class for all extraction problems."""


class ImageReadError(PhotoScanError):
    """The file is missing or is not a readable image."""


class NoEvidenceError(PhotoScanError):
    """The image is valid but does not contain a hidden manifesto."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_stepic(rgb_bytes):
    """Decode Stepic-style data from raw RGB bytes (R,G,B,R,G,B,... row by row).

    Returns the hidden bytes. Raises NoEvidenceError if no stop flag appears within
    MAX_MESSAGE_BYTES, which is what an image with nothing hidden in it looks like.
    """
    groups = len(rgb_bytes) // 9
    out = bytearray()
    for n in range(min(groups, MAX_MESSAGE_BYTES)):
        group = rgb_bytes[n * 9:(n + 1) * 9]
        byte = 0
        for value in group[:8]:
            byte = (byte << 1) | (value & 1)      # MSB first
        out.append(byte)
        if group[8] & 1:                          # stop flag
            return bytes(out)
    raise NoEvidenceError("no end-of-data flag found, so no hidden message is present")


def extract_manifesto(image_path, output_path=None):
    """Recover the manifesto from image_path and optionally save it to output_path.

    Returns a dict with the manifesto bytes and the evidence needed for the report.
    Raises ImageReadError or NoEvidenceError; never reports success without evidence.
    """
    path = Path(image_path)
    if not path.is_file():
        raise ImageReadError(f"image not found: {path}")

    hash_before = sha256_file(path)

    try:
        with Image.open(path) as img:                 # read-only; the image is never saved
            rgb_bytes = img.convert("RGB").tobytes()
    except (UnidentifiedImageError, OSError) as e:
        raise ImageReadError(f"cannot read image: {e}")

    raw = decode_stepic(rgb_bytes)

    # --- validate that what we decoded is really a manifesto, not noise ---
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise NoEvidenceError("decoded data is not valid text")
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable / len(text) < MIN_PRINTABLE_RATIO:
        raise NoEvidenceError("decoded data is mostly non-printable, so it is not a message")

    # --- completeness: the manifesto ends at the author's signature ---
    position = raw.rfind(SIGNATURE)
    if position == -1:
        raise NoEvidenceError("hidden data found, but it has no 'The Architect' signature")
    end = position + len(SIGNATURE)
    manifesto, trailing = raw[:end], raw[end:]

    # --- prove the original was not modified ---
    hash_after = sha256_file(path)
    if hash_after != hash_before:
        raise PhotoScanError("the original image changed during extraction")

    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(manifesto)

    return {
        "manifesto": manifesto,
        "text": manifesto.decode("utf-8"),
        "decoded_bytes": len(raw),           # everything Stepic stored (up to its stop flag)
        "trailing_bytes": trailing,          # anything after the signature that was discarded
        "pixels_used": (len(raw)) * 3,
        "image_sha256": hash_before,
        "manifesto_sha256": hashlib.sha256(manifesto).hexdigest(),
        "image_unchanged": True,
        "output_path": str(output_path) if output_path else None,
        "_raw": raw,
    }


def cross_check_with_stepic(image_path, raw):
    """Optional: confirm our decoder against the real stepic library (pip install stepic).

    Returns True/False, or None if stepic is not installed.
    """
    try:
        import stepic
    except ImportError:
        return None
    with Image.open(image_path) as img:
        decoded = stepic.decode(img.convert("RGB"))
    if isinstance(decoded, str):
        decoded = decoded.encode("utf-8")
    return decoded == raw


def main(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Recover the hidden manifesto from an image.")
    parser.add_argument("image", nargs="?", default="evidence/evidence.png")
    parser.add_argument("-o", "--output", default="evidence/architect_manifesto.txt")
    parser.add_argument("--cross-check", action="store_true", help="also verify with the stepic library")
    args = parser.parse_args(argv)

    try:
        result = extract_manifesto(args.image, args.output)
    except NoEvidenceError as e:
        print(f"NO EVIDENCE: {e}")
        return 3
    except PhotoScanError as e:
        print(f"ERROR: {e}")
        return 1

    print(f"Manifesto recovered ({len(result['manifesto'])} bytes) -> {result['output_path']}")
    print(f"  Image SHA-256:      {result['image_sha256']}")
    print(f"  Manifesto SHA-256:  {result['manifesto_sha256']}")
    print(f"  Manifesto Text:     {result['text']}")
    print()
    print(f"  Decoded {result['decoded_bytes']} bytes up to the stop flag; "
          f"{len(result['trailing_bytes'])} byte(s) after the signature discarded: {result['trailing_bytes']!r}")
    print("  Original image unchanged: yes")
    if args.cross_check:
        match = cross_check_with_stepic(args.image, result["_raw"])
        print("  stepic cross-check:", "not installed" if match is None else ("MATCH" if match else "MISMATCH"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))