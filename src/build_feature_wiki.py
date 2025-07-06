import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from mdutils.mdutils import MdUtils
from shutil import copy2

"""
This script generates Markdown wiki pages for each feature defined in
`edamame_security/features.json` and attaches the relevant screenshots.

Requirements:
1. `mdutils` – install with `pip install mdutils`
2. Screenshots should be collected beforehand. The script searches recursively
   in `--screenshots-dir` for PNG files matching sub-feature names
   (case-insensitive, ignoring numeric prefixes like '01_').

Usage::

    python build_feature_wiki.py --screenshots-dir ../edamame_app

Each generated *.md file will be created next to this script (or in
`--output-dir`). You can then push them to the GitHub wiki repo.
"""

import argparse
import re

FEATURES_PATH = Path(__file__).parent.with_name("features.json")

PREFIX_RE = re.compile(r"^\d+_+")  # matches numeric prefix like '01_'


def load_features() -> Dict:
    """Load features.json and return dict."""
    with FEATURES_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def sanitize_filename(name: str) -> str:
    """Return filesystem-safe lowercase filename."""
    return re.sub(r"[^a-z0-9_-]", "_", name.lower())


def find_screenshot(base_dir: Path, needle: str) -> Optional[Path]:
    """Search *recursively* for a PNG file whose stem matches *needle*.

    Numeric prefixes (e.g., '01_') in filenames are ignored during matching.
    Returns first match or None.
    """
    needle = needle.lower()
    for p in base_dir.rglob("*.png"):
        stem = PREFIX_RE.sub("", p.stem.lower())
        if stem == needle:
            return p
    return None


def write_feature_page(feature: Dict, screenshots_dir: Path, output_dir: Path, images_dir: Path, used_images: Set[Path]):
    slug = sanitize_filename(feature["name"])
    title_en = feature["title"]["en"]
    md = MdUtils(file_name=str(output_dir / f"feature-{slug}"), title=title_en)

    # Add description
    md.new_header(level=1, title=title_en)
    md.new_paragraph(feature["description"]["en"])

    # Embed a feature-level screenshot if exists (look for '<feature>.png')
    screenshot = find_screenshot(screenshots_dir, feature["name"])
    if screenshot:
        # copy into images dir for relative linking
        dest = images_dir / screenshot.name
        if dest not in used_images:
            copy2(screenshot, dest)
            used_images.add(dest)
        md.new_line(md.new_inline_image(text=title_en, path=f"images/{dest.name}"))

    # Sub-features
    for sub in feature.get("sub_features", []):
        sub_title = sub["title"]["en"]
        md.new_header(level=2, title=sub_title)
        md.new_paragraph(sub["description"]["en"])

        sub_shot = find_screenshot(screenshots_dir, sub["name"])
        if sub_shot:
            dest_sub = images_dir / sub_shot.name
            if dest_sub not in used_images:
                copy2(sub_shot, dest_sub)
                used_images.add(dest_sub)
            md.new_line(md.new_inline_image(text=sub_title, path=f"images/{dest_sub.name}"))

        # Items as bullet list
        items: List[Dict] = sub.get("items", [])
        if items:
            md.new_header(level=3, title="UI Elements & Data")
            for item in items:
                bullet = f"**{item['title']['en']}** – {item['description']['en']}"
                md.new_list([bullet])

    md.new_table_of_contents(table_title="Contents", depth=2)
    md.create_md_file()
    print(f"Generated {md.file_name}.md")
    return screenshot  # return for index page


def build_index(pages: List[Dict], output_dir: Path):
    """Generate Home.md index file linking to feature pages with thumbnails."""
    index = MdUtils(file_name=str(output_dir / "Home"), title="EDAMAME Feature Documentation")

    index.new_header(level=1, title="Feature Overview")
    index.new_paragraph("This wiki documents every major feature of EDAMAME Security with screenshots and a breakdown of underlying UI elements.")

    # Build table two columns (screenshot + link)
    headers = ["Feature", "Description"]
    table: List[str] = []
    for pg in pages:
        thumb_md = pg["thumb_md"] if pg["thumb_md"] else ""
        link_md = index.new_inline_link(link=f"feature-{pg['slug']}.md", text=pg["title"])
        table.extend([f"{thumb_md}\n{link_md}", pg["desc"]])

    index.new_table(columns=2, rows=len(pages)+1, text=headers+table, text_align="left")
    index.create_md_file()
    print("Generated Home.md")


def main():
    parser = argparse.ArgumentParser(description="Generate feature wiki pages with screenshots.")
    parser.add_argument("--screenshots-dir", required=True, type=Path, help="Directory containing PNG screenshots")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd(), help="Where to write markdown files")
    args = parser.parse_args()

    screenshots_dir: Path = args.screenshots_dir.resolve()
    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    images_dir = output_dir / "images"
    images_dir.mkdir(exist_ok=True)

    used_images: Set[Path] = set()

    index_pages: List[Dict] = []

    data = load_features()
    for feature in data.get("features", []):
        slug = sanitize_filename(feature["name"])
        thumb = write_feature_page(
            feature,
            screenshots_dir,
            output_dir,
            images_dir,
            used_images,
        )
        thumb_md = f"![{feature['title']['en']}](images/{thumb.name})" if thumb else ""
        index_pages.append(
            {
                "slug": slug,
                "title": feature["title"]["en"],
                "thumb_md": thumb_md,
                "desc": feature["description"]["en"],
            }
        )

    build_index(index_pages, output_dir)


if __name__ == "__main__":
    main() 