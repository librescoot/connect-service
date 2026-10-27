# Shared Librescoot website assets

`assets/style.css`, `assets/fonts/`, `assets/images/` and `assets/theme-toggle.js` are unchanged copies from [librescoot/librescoot.github.io](https://github.com/librescoot/librescoot.github.io), revision `6d252cc5fd555a7432f9e7429b966b5fdda50808`. The downloads site uses the same website stylesheet and fonts. `assets/LICENSE.website` preserves the website's license. The fonts retain SIL Open Font License 1.1; `assets/fonts/LICENSE.abel`, `LICENSE.hankengrotesk` and `LICENSE.jetbrainsmono` preserve the upstream copyright and license notices.

The pairing template reuses the website's `nav`, `nav-docs`, `nav-container`, `logo-small`, `nav-controls`, `docs-main`, `container`, `lead`, `docs-grid`, `docs-card`, `btn`, `btn-primary`, `info-box`, `warning-box` and footer components. `theme-init.js` extracts the website/downloads theme bootstrap into a same-origin script for CSP compatibility.

`pair.css` contains only pairing form layout and controls absent from the website stylesheet. Use the shared design tokens and components; do not redefine the site's palette, typography, branding or buttons here. Refresh the copied assets from the website together and update the pinned asset checks in `web_test.go`.

Assets are embedded and served locally. Pairing does not request fonts, CSS or images from another site.
