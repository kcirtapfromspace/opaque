"""Adversarial generated-artifact fixtures; never deploy or read private services."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest

import check_site_privacy as privacy


class SitePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.site = Path(self.temporary.name)
        (self.site / "search").mkdir()
        (self.site / "assets").mkdir()
        (self.site / "index.html").write_text("<h1>Visitor documentation</h1>")
        (self.site / "search/search_index.json").write_text(json.dumps({"docs": [{"location": "", "text": "Visitor"}]}))
        (self.site / "sitemap.xml").write_text('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://opaque.info/</loc></url></urlset>')

    def test_valid_generated_site_is_accepted(self):
        self.assertEqual(privacy.inspect_site(self.site, "PRIVATEFIXTURE"), [])

    def test_every_output_kind_is_scanned_for_private_source_content(self):
        for name in ("index.html", "assets/copy.bin", "assets/bundle.js", "assets/copy.txt.gz"):
            with self.subTest(name=name):
                path = self.site / name
                prior = path.read_bytes() if path.exists() else None
                raw = b"PRIVATEFIXTURE"
                path.write_bytes(gzip.compress(raw) if name.endswith(".gz") else raw)
                self.assertTrue(any("sentinel leaked" in failure for failure in privacy.inspect_site(self.site, raw.decode())))
                if prior is None:
                    path.unlink()
                else:
                    path.write_bytes(prior)

    def test_private_and_unreviewed_html_routes_fail_outside_navigation(self):
        for name in ("product/report/index.html", "dogfood/index.html", "unreviewed/index.html"):
            with self.subTest(name=name):
                path = self.site / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("<h1>Not in navigation</h1>")
                self.assertTrue(any("allowlist" in failure for failure in privacy.inspect_site(self.site)))
                path.unlink()

    def test_search_and_sitemap_are_validated_as_data(self):
        (self.site / "search/search_index.json").write_text(json.dumps({"docs": [{"location": "unreviewed/#section"}]}))
        (self.site / "sitemap.xml").write_text('<urlset><url><loc>https://opaque.info/%70roduct/internal/</loc></url></urlset>')
        failures = privacy.inspect_site(self.site)
        self.assertTrue(any("non-visitor route indexed" in failure and "search" in failure for failure in failures))
        self.assertTrue(any("non-visitor route indexed" in failure and "sitemap" in failure for failure in failures))

    def test_compressed_sitemap_cannot_hide_different_routes(self):
        path = self.site / "sitemap.xml.gz"
        path.write_bytes(gzip.compress((self.site / "sitemap.xml").read_bytes()))
        self.assertEqual(privacy.inspect_site(self.site), [])
        path.write_bytes(gzip.compress(b"<urlset><url><loc>https://opaque.info/unreviewed/</loc></url></urlset>"))
        self.assertTrue(any("compressed sitemap differs" in failure for failure in privacy.inspect_site(self.site)))

    def test_missing_and_malformed_evidence_fails_closed(self):
        (self.site / "search/search_index.json").write_text("null")
        (self.site / "sitemap.xml").unlink()
        failures = privacy.inspect_site(self.site)
        self.assertTrue(any("malformed search" in failure for failure in failures))
        self.assertTrue(any("missing" in failure for failure in failures))

    def test_private_sources_and_raw_asset_receive_the_build_sentinel(self):
        docs = self.site / "docs"
        (docs / "product").mkdir(parents=True)
        (docs / "product/review.md").write_text("# Private review")
        self.assertGreater(privacy.mark_private_sources(docs, "PRIVATEFIXTURE"), 4)
        for name in ("product/review.md", "product/privacy-check.md", "product/privacy-check.txt", "dogfood.md", "release-dogfood.md", "tenant-boundaries.md", "README.md"):
            self.assertIn("PRIVATEFIXTURE", (docs / name).read_text())

    def test_encoded_private_links_and_opaque_archives_are_rejected(self):
        (self.site / "index.html").write_text('<a href="/%2570roduct/report/">private</a>')
        (self.site / "assets/uninspected.zip").write_bytes(b"not inspectable")
        failures = privacy.inspect_site(self.site)
        self.assertTrue(any("private document route" in failure for failure in failures))
        self.assertTrue(any("inspection failed" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
