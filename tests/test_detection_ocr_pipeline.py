import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))


class PdfParserOcrTests(unittest.TestCase):
    def test_scanned_pdf_page_is_rendered_for_ocr(self):
        import fitz
        from detection.parsers import extract_file_content

        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "scanned.pdf"
            doc = fitz.open()
            doc.new_page(width=220, height=120)
            doc.save(pdf_path)
            doc.close()

            result = extract_file_content(pdf_path)

        self.assertEqual(result["parse_status"], "ok")
        self.assertEqual(result["pdf_type"], "scanned_pdf")
        self.assertTrue(result["needs_ocr"])
        self.assertEqual(result["pages_without_text"], 1)
        self.assertEqual(result["pdf_meta"]["rendered_pages_for_ocr"], 1)
        self.assertEqual(result["image_blocks"][0]["source_type"], "pdf_page_render")
        self.assertTrue(result["image_blocks"][0]["bytes"].startswith(b"\x89PNG"))

    def test_text_pdf_does_not_render_text_pages_for_ocr(self):
        import fitz
        from detection.parsers import extract_file_content

        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "text.pdf"
            doc = fitz.open()
            page = doc.new_page(width=220, height=120)
            page.insert_text((20, 60), "normal text")
            doc.save(pdf_path)
            doc.close()

            result = extract_file_content(pdf_path)

        self.assertEqual(result["pdf_type"], "text_pdf")
        self.assertFalse(result["needs_ocr"])
        self.assertEqual(result["pdf_meta"]["rendered_pages_for_ocr"], 0)
        self.assertEqual(result["image_blocks"], [])


class DetectionPipelineOcrTests(unittest.TestCase):
    def test_corrupted_pdf_parse_failure_is_preserved(self):
        from detection import pipeline

        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "broken.pdf"
            pdf_path.write_bytes(b"%PDF-1.4\nbroken")

            with mock.patch.object(pipeline, "get_enabled_rules", return_value=[]):
                result = pipeline.detect_file(
                    pdf_path,
                    agent_id="agent-1",
                    scan_id="scan-1",
                    file_meta={
                        "path": str(pdf_path),
                        "size": pdf_path.stat().st_size,
                        "extension": ".pdf",
                        "sha256": "hash-broken",
                    },
                )

        self.assertEqual(result["parse_status"], "failed")
        self.assertTrue(result["parse_error"])
        self.assertEqual(result["risk_level"], "REVIEW")
        self.assertEqual(result["final_decision"]["source"], "parser")
        self.assertEqual(result["final_decision"]["reason"], "parse_failed")
        self.assertFalse(result["final_decision"]["is_sensitive"])

    def test_image_ocr_text_enters_rule_findings(self):
        from PIL import Image
        from detection import pipeline

        ocr_rule = {
            "rule_id": "ocr-sensitive-words",
            "rule_name": "OCR sensitive words",
            "rule_type": "ocr",
            "enabled": True,
            "config": {
                "keywords": ["绝密", "密码"],
                "apply_file_types": ["png", "jpg", "jpeg", "bmp", "pdf"],
                "case_sensitive": False,
            },
        }

        def fake_enabled_rules(rule_type=None):
            if rule_type == "ocr":
                return [ocr_rule]
            return []

        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "sample.png"
            Image.new("RGB", (180, 80), "white").save(image_path)

            with mock.patch.object(pipeline, "get_enabled_rules", side_effect=fake_enabled_rules), \
                mock.patch.object(
                    pipeline,
                    "extract_text_from_image_bytes",
                    return_value=[{"text": "项目资料 绝密 密码", "bbox": [[0, 0], [80, 0], [80, 20], [0, 20]], "location": "image:sample.png"}],
                ):
                result = pipeline.detect_file(
                    image_path,
                    agent_id="agent-1",
                    scan_id="scan-1",
                    file_meta={
                        "path": str(image_path),
                        "size": image_path.stat().st_size,
                        "extension": ".png",
                        "sha256": "hash-1",
                    },
                )

        matched = {item["matched_text"] for item in result["ocr_findings"]}
        self.assertIn("绝密", matched)
        self.assertIn("密码", matched)
        self.assertTrue(result["final_decision"]["is_sensitive"])
        self.assertEqual(result["final_decision"]["source"], "ocr")
        self.assertEqual(result["image_block_count"], 1)


class OcrServicePreprocessingTests(unittest.TestCase):
    def test_run_ocr_uses_best_preprocessed_variant(self):
        import ocr_service
        from PIL import Image
        import io

        class FakeModel:
            def __init__(self):
                self.calls = 0

            def predict(self, _img):
                self.calls += 1
                if self.calls == 1:
                    return [{"rec_texts": [], "rec_boxes": []}]
                return [{"rec_texts": ["绝密"], "rec_boxes": [[10, 10, 80, 30]]}]

        image = Image.new("RGB", (160, 80), "white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        fake_model = FakeModel()

        with mock.patch.object(ocr_service, "get_ocr_model", return_value=fake_model):
            rows = ocr_service.run_ocr(buffer.getvalue(), "image:test")

        self.assertEqual(rows[0]["text"], "绝密")
        self.assertEqual(rows[0]["location"], "image:test")
        self.assertGreaterEqual(fake_model.calls, 2)


if __name__ == "__main__":
    unittest.main()
