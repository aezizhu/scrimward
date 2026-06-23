"""On-device image redaction via Apple Vision — strict fill-all, fail-closed.

macOS + Apple Silicon only (Apple Vision has no portable equivalent). The text
engine can't see inside images, so by default every image fails closed (refused).
When enabled the strategy is deliberately STRICT and geometry-first:

- Cover EVERY detected text region and face with a SOLID OPAQUE box — never blur
  or pixelate (those are mathematically reversible).
- Never gate the fill on what OCR *read*: Apple Vision's transcription is
  unreliable (it garbles secrets — observed "AKIAIOSFODNN7EXAMPLE" → "…EXAMI"),
  so a detector-gated fill would leave the very keys we must hide on the wire.
- Use BOTH recognition (VNRecognizeText) and detection (VNDetectTextRectangles —
  detection recall > recognition recall) plus face rectangles, so detected-but-
  unreadable text is still covered.
- After filling, RE-SCAN the filled image with the SAME detectors (recognition
  + detection + faces) and REFUSE (raise) on ANY residual region — the
  fail-closed safety net, with no confidence tolerance (text re-reading even at
  low confidence is still readable, so it must not ship).

Recall ceiling (documented, not hidden): text Vision cannot detect AT ALL (very
low contrast, extreme rotation, tiny fonts) may be missed. Callers who cannot
tolerate that residual risk should keep images failing closed.
"""

from __future__ import annotations

import functools
import io

# Pad each fill box by this fraction of its size (OCR clips glyph edges + anti-alias).
_PAD = 0.10
# Provider media types we can decode + re-encode losslessly enough to redact.
_SUPPORTED: dict[str, str] = {"image/png": "PNG", "image/jpeg": "JPEG", "image/jpg": "JPEG"}


class ImageRedactionError(RuntimeError):
    """An image could not be SAFELY redacted → the caller must fail closed."""


@functools.lru_cache(maxsize=1)
def _stack():
    """Import the Vision + Quartz + Pillow stack once; return it or ``None``."""
    try:
        import Vision
        from Foundation import NSData
        from PIL import Image, ImageDraw

        return (Vision, NSData, Image, ImageDraw)
    except Exception:
        return None


@functools.lru_cache(maxsize=1)
def image_redaction_available() -> bool:
    """True only if Apple Vision OCR actually runs here (memoized self-test)."""
    stack = _stack()
    if stack is None:
        return False
    vision, nsdata_cls, image_cls, _ = stack
    try:
        buf = io.BytesIO()
        image_cls.new("RGB", (32, 32), "white").save(buf, "PNG")
        raw = buf.getvalue()
        nsdata = nsdata_cls.dataWithBytes_length_(raw, len(raw))
        handler = vision.VNImageRequestHandler.alloc().initWithData_options_(nsdata, {})
        req = vision.VNRecognizeTextRequest.alloc().init()
        handler.performRequests_error_([req], None)
        return True
    except Exception:
        return False


def _run(vision, nsdata_cls, raw: bytes, req) -> list:
    nsdata = nsdata_cls.dataWithBytes_length_(raw, len(raw))
    handler = vision.VNImageRequestHandler.alloc().initWithData_options_(nsdata, {})
    _ok, err = handler.performRequests_error_([req], None)
    if err is not None:
        raise ImageRedactionError(f"vision request failed: {err}")
    return list(req.results() or [])


def _detect_boxes(vision, nsdata_cls, raw: bytes) -> list[tuple[float, float, float, float]]:
    """All normalized (bottom-left) boxes to cover: recognized + detected text + faces."""
    boxes: list[tuple[float, float, float, float]] = []

    recognize = vision.VNRecognizeTextRequest.alloc().init()
    recognize.setRecognitionLevel_(vision.VNRequestTextRecognitionLevelAccurate)
    detect = vision.VNDetectTextRectanglesRequest.alloc().init()
    faces = vision.VNDetectFaceRectanglesRequest.alloc().init()

    for req in (recognize, detect, faces):
        for obs in _run(vision, nsdata_cls, raw, req):
            bb = obs.boundingBox()
            boxes.append((bb.origin.x, bb.origin.y, bb.size.width, bb.size.height))
    return boxes


def _to_pixel_rect(box, width: int, height: int) -> tuple[int, int, int, int]:
    """Normalized bottom-left box → padded integer top-left pixel rect."""
    x, y, w, h = box
    x -= w * _PAD
    y -= h * _PAD
    w *= 1 + 2 * _PAD
    h *= 1 + 2 * _PAD
    left = max(0, int(x * width))
    right = min(width, int((x + w) * width))
    # Flip Y: Vision's origin is bottom-left, Pillow's is top-left.
    top = max(0, int((1.0 - y - h) * height))
    bottom = min(height, int((1.0 - y) * height))
    return left, top, right, bottom


def redact_image_bytes(raw: bytes, media_type: str) -> bytes:
    """Return ``raw`` with every text region + face covered by an opaque box.

    Raises :class:`ImageRedactionError` on ANY doubt — Vision unavailable,
    unsupported/undecodable format, a Vision failure, or readable text surviving
    the re-verify pass — so the caller forwards NOTHING (fail-closed).
    """
    stack = _stack()
    if stack is None:
        raise ImageRedactionError("apple vision is unavailable on this machine")
    vision, nsdata_cls, image_cls, imagedraw_cls = stack

    fmt = _SUPPORTED.get((media_type or "").lower())
    if fmt is None:
        raise ImageRedactionError(f"unsupported image media type {media_type!r}")
    try:
        img = image_cls.open(io.BytesIO(raw)).convert("RGB")
    except Exception as exc:
        raise ImageRedactionError(f"cannot decode image: {exc}") from exc

    width, height = img.size
    boxes = _detect_boxes(vision, nsdata_cls, raw)
    draw = imagedraw_cls.Draw(img)
    for box in boxes:
        left, top, right, bottom = _to_pixel_rect(box, width, height)
        if right > left and bottom > top:
            draw.rectangle([left, top, right, bottom], fill=(0, 0, 0))

    out = io.BytesIO()
    img.save(out, fmt)
    redacted = out.getvalue()

    # Fail-closed safety net: re-scan the FILLED image with the SAME detectors.
    # A clean fill leaves zero regions; ANY residual (recognized text, detected
    # text rectangle, or face) means the fill missed something → refuse. No
    # confidence tolerance — pass-1 fills unconditionally, so any survivor is real.
    if _detect_boxes(vision, nsdata_cls, redacted):
        raise ImageRedactionError(
            "text or a face survived redaction; refusing to forward (fail-closed)"
        )
    return redacted
