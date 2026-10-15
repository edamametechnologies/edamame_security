# Contributing to the EDAMAME Security documentation

This repository is the public home of EDAMAME Security: the README, the
[feature wiki](https://github.com/edamametechnologies/edamame_security/wiki)
and the screenshots both use, the releases, and the issue tracker. The app
itself is closed source and built elsewhere.

**The README is customer-facing.** Write it for customers and administrators:
what the app does, for whom, how to install it, how to use it, and how to get
help. Keep out internal operations (hostnames, CI runs, internal documents,
people, customers) and anything about vulnerabilities or detection internals.
Maintainer material belongs here.

## Repository layout

```
├── README.md                    # Customer-facing overview, installation, user guide, troubleshooting
├── features.json                # Features, sub-features and screenshot mappings (en/fr) for the wiki
├── privacy-LLM-EN.md            # Portal AI service privacy policy (also -FR)
├── macos/screenshots/           # Screenshots per platform: the README uses macos/,
├── windows/screenshots/         #   the wiki every platform
├── linux/screenshots/
├── ios/screenshots/             # iOS: one subdirectory per device class
├── android/screenshots/
├── chocolatey/                  # Source of the edamame Chocolatey package
├── src/build_feature_wiki.py    # Wiki markdown generation
└── .github/workflows/
    └── feature-wiki.yml         # Wiki publish on every push to main
```

## How the screenshots stay current

The screenshots are never captured by hand:

1. Whenever the app's interface changes on its main branch, the app's CI runs
   its screenshot walkthrough: a Flutter integration test that opens every
   screen in demo mode (simulated data, no account) and renders the macOS,
   Windows, Linux, iOS and Android layouts.
2. It replaces each platform's `screenshots/` directory here with the new
   captures and commits them to `main` as `EDAMAME Dev`
   (`chore: Update screenshots from edamame_app (main)`). A platform whose
   capture failed keeps its previous screenshots.
3. That push runs `feature-wiki.yml`, which rebuilds the wiki from
   `features.json` and `macos/` and publishes it.

The README embeds only files the walkthrough produces (named
`{prefix}_{name}.png` from `features.json`), so it follows the app without
anyone editing it. When a screen is renamed or removed, update the README in
the same change.

CI only ever adds commits to `main`. Screenshot commits accumulate, so the
maintainers occasionally squash the history of `main` into a single commit,
outside CI, and move the release tags onto it; do not build on old screenshot
commits.

## Releases

The `vX.Y.Z` tags and their release pages, with the signed installers, are
published here by the app's release workflow. Do not create or move tags by
hand. Release notes follow the same rules as the README: what changes for
users, never vulnerabilities or detection internals.

The `chocolatey/` directory is the source of the `edamame` Chocolatey package,
and its only copy: the app's release workflow packs it as it is here, setting
the version, download URL and checksum, and adds `tools/install_msix.ps1`, the
MSIX installer the app's Windows bundle ships too (it is in every published
package). Change the package here.

## features.json

`features` lists the wiki's feature pages, each with `name`, `title` and
`description` in `en` and `fr`, and `sub_features`. The screenshot of a
sub-feature is found through `screenshot_metadata.sub_feature_mappings`:

- `prefix`: the file name is `{prefix}_{name}.png`;
- `multipane: true`: desktop layouts with a selected pane also have
  `{prefix}_{name}_selected.png`, which the wiki shows instead;
- `has_scroll_screenshots: true`: a long page is also captured as an ordered
  `{prefix}_{name}_scroll{N}.png` sequence, shown below the first image.

A new screen needs its entry here and a capture in the app's walkthrough; the
next walkthrough run commits its screenshots.

## Building the wiki locally

```bash
pip install mdutils
python src/build_feature_wiki.py --screenshots-dir macos --output-dir wiki
```

The workflow publishes the generated pages and images to the
[wiki](https://github.com/edamametechnologies/edamame_security/wiki); never
edit the wiki by hand, it is overwritten on the next run.
