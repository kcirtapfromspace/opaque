"""Shared asset publication must be local, licensed, complete, and allowlisted."""

import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

import mkdocs_brand as brand


class BrandAssetTests(unittest.TestCase):
    def test_manifest_matches_rust_allowlist_and_all_css_resources_are_local(self):
        source = brand.ROOT / "assets/brand"
        names = set(brand.asset_paths(source))
        embedded = (source / "embedded.rs").read_text()
        self.assertEqual(names, set(re.findall(r'include_bytes!\("([^"]+)"\)', embedded)))
        self.assertNotIn("embedded.rs", names)
        self.assertNotIn("manifest.json", names)
        css = (source / "opaque.css").read_text()
        for url in re.findall(r'url\("([^"]+)"\)', css):
            self.assertIn(url, names)
            self.assertNotIn(":", url)
            self.assertTrue(url.startswith("fonts/"))
        manifest = json.loads((source / "manifest.json").read_text())
        fonts = [asset for asset in manifest["assets"] if asset["path"].endswith(".ttf")]
        self.assertEqual(len(fonts), 6)
        for asset in fonts:
            self.assertIn(asset["license"], names)
            self.assertTrue(asset["upstream_url"].startswith("https://raw.githubusercontent.com/google/fonts/"))
            self.assertTrue((source / asset["path"]).read_bytes().startswith(b"\x00\x01\x00\x00"))
            self.assertIn("SIL OPEN FONT LICENSE", (source / asset["license"]).read_text())

    def test_asset_corruption_missing_files_traversal_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve() / "brand"
            shutil.copytree(brand.ROOT / "assets/brand", source)
            font = source / "fonts/archivo-variable.ttf"
            original = font.read_bytes()
            font.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "differs"):
                brand.asset_paths(source)
            font.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                brand.asset_paths(source)
            outside = source.parent / "outside.ttf"
            outside.write_bytes(original)
            font.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                brand.asset_paths(source)
            font.unlink()
            font.write_bytes(original)
            manifest = json.loads((source / "manifest.json").read_text())
            manifest["assets"][0]["path"] = "../outside.ttf"
            (source / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "invalid"):
                brand.asset_paths(source)


if __name__ == "__main__":
    unittest.main()
