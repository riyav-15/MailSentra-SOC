from urllib.parse import urlparse


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}


def is_supported_image(file_name: str | None, content_type: str | None = None) -> bool:
    lowered = (file_name or "").lower()
    if any(lowered.endswith(extension) for extension in IMAGE_EXTENSIONS):
        return True
    return bool(content_type and content_type.lower().startswith("image/"))


def extract_qr_payloads_from_bytes(content: bytes, file_name: str | None = None, content_type: str | None = None) -> list[dict]:
    if not content or not is_supported_image(file_name, content_type):
        return []

    try:
        import cv2
        import numpy as np
    except ImportError:
        return []

    image = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []

    detector = cv2.QRCodeDetector()
    payloads: list[str] = []

    try:
        ok, decoded_info, _, _ = detector.detectAndDecodeMulti(image)
        if ok:
            payloads.extend(item for item in decoded_info if item)
    except Exception:
        pass

    if not payloads:
        try:
            payload, _, _ = detector.detectAndDecode(image)
            if payload:
                payloads.append(payload)
        except Exception:
            pass

    seen = set()
    indicators = []
    for payload in payloads:
        if payload in seen:
            continue
        seen.add(payload)
        indicators.append(
            {
                "payload": payload,
                "is_url": is_url(payload),
                "domain": domain_from_url(payload),
                "source": file_name or "uploaded_image",
            }
        )
    return indicators


def is_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def domain_from_url(value: str) -> str:
    if not is_url(value):
        return ""
    return (urlparse(value.strip()).hostname or "").lower().rstrip(".")
