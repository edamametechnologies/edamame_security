import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from mdutils.mdutils import MdUtils
from shutil import copy2

"""
This script generates beautiful Markdown wiki pages for each feature defined in
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
SELECTED_SUFFIX = "_selected"  # suffix for multi-pane selection screenshots


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


def find_dual_screenshots(base_dir: Path, needle: str) -> tuple[Optional[Path], Optional[Path]]:
    """Search for both regular and selected screenshots.
    
    Returns tuple of (regular_screenshot, selected_screenshot).
    """
    regular = find_screenshot(base_dir, needle)
    selected = find_screenshot(base_dir, f"{needle}{SELECTED_SUFFIX}")
    return (regular, selected)


def add_feature_badge(md: MdUtils, feature_name: str):
    """Add a feature badge/label for visual appeal."""
    badge_color = "blue"
    badge_text = f"Feature: {feature_name}"
    badge_url = f"https://img.shields.io/badge/{badge_text.replace(' ', '%20').replace(':', '%3A')}-{badge_color}"
    md.new_line(f"![{badge_text}]({badge_url})")
    md.new_line()


def add_screenshot_with_caption(md: MdUtils, screenshot_path: Path, title: str, caption: str = None):
    """Add a properly formatted screenshot with caption and styling."""
    if not caption:
        caption = title
    
    # Create a centered image with caption
    md.new_line()
    md.new_line("---")
    md.new_line()
    md.new_line(f"<div align=\"center\">")
    md.new_line()
    md.new_line(f"![{title}](images/{screenshot_path.name})")
    md.new_line()
    md.new_line(f"*{caption}*")
    md.new_line()
    md.new_line("</div>")
    md.new_line()
    md.new_line("---")
    md.new_line()


def add_dual_screenshots(md: MdUtils, regular_path: Path, selected_path: Path, title: str, caption: str = None):
    """Add two screenshots side by side (list view + detail view) for multi-pane features."""
    if not caption:
        caption = title
    
    md.new_line()
    md.new_line("---")
    md.new_line()
    md.new_line(f"<div align=\"center\">")
    md.new_line()
    md.new_line("| List View | Detail View |")
    md.new_line("|:---:|:---:|")
    md.new_line(f"| ![{title} - List](images/{regular_path.name}) | ![{title} - Detail](images/{selected_path.name}) |")
    md.new_line()
    md.new_line(f"*{caption} - Multi-pane layout showing list and detail views*")
    md.new_line()
    md.new_line("</div>")
    md.new_line()
    md.new_line("---")
    md.new_line()


def write_feature_page(feature: Dict, screenshots_dir: Path, output_dir: Path, images_dir: Path, used_images: Set[Path]):
    slug = sanitize_filename(feature["name"])
    title_en = feature["title"]["en"]
    has_dual = feature.get("has_dual_screenshots", False)
    md = MdUtils(file_name=str(output_dir / f"feature-{slug}"), title=title_en)

    # Add front matter style header
    md.new_line("---")
    md.new_line()
    
    # Add feature badge
    add_feature_badge(md, feature["name"])

    # Add main title with emoji
    md.new_header(level=1, title=f"🔐 {title_en}")
    md.new_line()
    
    # Add description in a styled block
    md.new_line("> **Overview**")
    md.new_line(f"> {feature['description']['en']}")
    md.new_line()

    # Embed a feature-level screenshot if exists (check for dual screenshots)
    screenshot, selected_screenshot = find_dual_screenshots(screenshots_dir, feature["name"])
    
    if screenshot:
        dest = images_dir / screenshot.name
        if dest not in used_images:
            copy2(screenshot, dest)
            used_images.add(dest)
        
        # Check for selected screenshot for dual display
        dest_selected = None
        if selected_screenshot and has_dual:
            dest_selected = images_dir / selected_screenshot.name
            if dest_selected not in used_images:
                copy2(selected_screenshot, dest_selected)
                used_images.add(dest_selected)
        
        md.new_header(level=2, title="🖼️ Feature Overview")
        if dest_selected:
            add_dual_screenshots(md, dest, dest_selected, title_en, f"Main interface for {title_en}")
        else:
            add_screenshot_with_caption(md, dest, title_en, f"Main interface for {title_en}")

    # Sub-features with better formatting
    sub_features = feature.get("sub_features", [])
    if sub_features:
        md.new_header(level=2, title="⚙️ Sub-Features")
        md.new_line()
        
        for i, sub in enumerate(sub_features, 1):
            sub_title = sub["title"]["en"]
            sub_has_dual = sub.get("has_dual_screenshots", has_dual)  # Inherit from parent if not set
            
            # Add sub-feature header with numbering and icon
            md.new_header(level=3, title=f"{i}. 🔧 {sub_title}")
            md.new_line()
            
            # Add description in a styled format
            md.new_line("**Description:**")
            md.new_line(f"{sub['description']['en']}")
            md.new_line()

            # Add screenshot if available (check for dual screenshots)
            sub_shot, sub_shot_selected = find_dual_screenshots(screenshots_dir, sub["name"])
            if sub_shot:
                dest_sub = images_dir / sub_shot.name
                if dest_sub not in used_images:
                    copy2(sub_shot, dest_sub)
                    used_images.add(dest_sub)
                
                # Check for selected screenshot for dual display
                dest_sub_selected = None
                if sub_shot_selected and sub_has_dual:
                    dest_sub_selected = images_dir / sub_shot_selected.name
                    if dest_sub_selected not in used_images:
                        copy2(sub_shot_selected, dest_sub_selected)
                        used_images.add(dest_sub_selected)
                
                if dest_sub_selected:
                    add_dual_screenshots(md, dest_sub, dest_sub_selected, sub_title, f"Screenshot of {sub_title}")
                else:
                    add_screenshot_with_caption(md, dest_sub, sub_title, f"Screenshot of {sub_title}")

            # Items as a well-formatted list
            items: List[Dict] = sub.get("items", [])
            if items:
                md.new_header(level=4, title="📝 UI Elements & Data")
                md.new_line()
                
                # Create a more structured list
                for item in items:
                    md.new_line(f"- **{item['title']['en']}**")
                    md.new_line(f"  - {item['description']['en']}")
                    md.new_line()

            # Add a styled separator between sub-features
            if i < len(sub_features):
                md.new_line()
                md.new_line("---")
                md.new_line()

    # Add table of contents at the end to avoid conflicts
    md.new_header(level=2, title="📋 Contents")
    md.new_table_of_contents(table_title="", depth=3)
    md.new_line()

    # Add footer with navigation
    md.new_line()
    md.new_line("---")
    md.new_line()
    md.new_header(level=2, title="🏠 Navigation")
    md.new_line("- [← Back to Feature Overview](Home)")
    md.new_line("- [📖 Full Documentation](https://github.com/edamametechnologies/edamame_security/wiki)")
    md.new_line()
    
    # Add metadata footer
    md.new_line("---")
    md.new_line("*This page was automatically generated from feature definitions.*")
    md.new_line()

    md.create_md_file()
    print(f"✅ Generated {md.file_name}.md")
    return screenshot


def build_index(pages: List[Dict], output_dir: Path):
    """Generate beautiful Home.md index file linking to feature pages with thumbnails."""
    index = MdUtils(file_name=str(output_dir / "Home"), title="EDAMAME Security - Feature Documentation")

    # Add beautiful header with raw markdown to avoid TOC conflicts
    index.new_line("---")
    index.new_line()
    index.new_line("<div align=\"center\">")
    index.new_line()
    index.new_line("# 🔐 EDAMAME Security")
    index.new_line("## Feature Documentation")
    index.new_line()
    index.new_line("![EDAMAME](https://img.shields.io/badge/EDAMAME-Security-blue?style=for-the-badge)")
    index.new_line("![Features](https://img.shields.io/badge/Features-" + str(len(pages)) + "-green?style=for-the-badge)")
    index.new_line()
    index.new_line("</div>")
    index.new_line()
    index.new_line("---")
    index.new_line()

    # Add overview section using raw markdown
    index.new_line("## 📖 Overview")
    index.new_line()
    index.new_line("> This wiki documents every major feature of EDAMAME Security with detailed screenshots,")
    index.new_line("> comprehensive descriptions, and a complete breakdown of UI elements and functionality.")
    index.new_line()

    # Add quick navigation using raw markdown
    index.new_line("## 🚀 Quick Navigation")
    index.new_line()
    
    # Create a grid-like structure for features
    for i, pg in enumerate(pages, 1):
        feature_link = index.new_inline_link(link=f"feature-{pg['slug']}", text=pg["title"])
        index.new_line(f"{i}. {feature_link}")
    
    index.new_line()
    index.new_line("---")
    index.new_line()

    # Add detailed feature cards using raw markdown
    index.new_line("## 📋 Feature Details")
    index.new_line()
    
    for pg in pages:
        # Create a card-like structure for each feature
        index.new_line("### " + pg["title"])
        index.new_line()
        
        # Add thumbnail if available
        if pg["thumb_md"]:
            index.new_line("<div align=\"center\">")
            index.new_line()
            index.new_line(pg["thumb_md"])
            index.new_line()
            index.new_line("</div>")
            index.new_line()
        
        # Add description
        index.new_line(f"**Description:** {pg['desc']}")
        index.new_line()
        
        # Add action button
        feature_link = index.new_inline_link(link=f"feature-{pg['slug']}", text="📖 View Details")
        index.new_line(f"**Action:** {feature_link}")
        index.new_line()
        index.new_line("---")
        index.new_line()

    # Add footer using raw markdown
    index.new_line()
    index.new_line("---")
    index.new_line()
    index.new_line("## ℹ️ About")
    index.new_line()
    index.new_line("- **Repository:** [EDAMAME Security](https://github.com/edamametechnologies/edamame_security)")
    index.new_line("- **Documentation:** Auto-generated from feature definitions")
    index.new_line("- **Last Updated:** " + str(Path().cwd().stat().st_mtime))
    index.new_line()
    index.new_line("---")
    index.new_line()
    index.new_line("<div align=\"center\">")
    index.new_line()
    index.new_line("*Made with ❤️ by the EDAMAME Team*")
    index.new_line()
    index.new_line("</div>")
    index.new_line()

    index.create_md_file()
    print("✅ Generated beautiful Home.md")


def main():
    parser = argparse.ArgumentParser(description="Generate beautiful feature wiki pages with screenshots.")
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

    print("🚀 Starting beautiful wiki generation...")
    print(f"📁 Screenshots directory: {screenshots_dir}")
    print(f"📁 Output directory: {output_dir}")
    print()

    data = load_features()
    features = data.get("features", [])
    
    print(f"📊 Processing {len(features)} features...")
    print()

    for feature in features:
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

    print()
    build_index(index_pages, output_dir)
    print()
    print("🎉 Beautiful wiki generation complete!")
    print(f"📄 Generated {len(features)} feature pages + 1 index page")
    print(f"🖼️ Processed {len(used_images)} screenshots")


if __name__ == "__main__":
    main() 