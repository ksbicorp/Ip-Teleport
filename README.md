<p align="center">
  <img src="teleport-extension/icons/icon128.png" alt="IP-Teleport icon" width="128" height="128">
</p>

<h1 align="center">IP-Teleport</h1>

<p align="center">
  Browser-based infrastructure exposure review for authorized security testing.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white" alt="Chrome Manifest V3">
  <img src="https://img.shields.io/badge/JavaScript-extension-F7DF1E?logo=javascript&logoColor=222" alt="JavaScript">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="Apache 2.0 license">
</p>

> **Authorized use only.** Use this extension only on systems you own or are explicitly authorized to assess. Do not use it to bypass protections, probe third-party infrastructure, or access data without permission. Follow applicable laws, provider terms, and responsible disclosure practices.

## Overview

IP-Teleport is a Chrome Manifest V3 extension for reviewing network exposure indicators associated with the active browsing context. Depending on the configured integrations and available data, it can present public-IP and infrastructure intelligence in the browser.

This project is intended for defensive assessment and security research within a clearly authorized scope. Results are third-party data and may be incomplete, stale, or inaccurate; independently validate findings before acting on them.

## Install in Chrome

1. Download or clone this repository, then extract it if you downloaded a ZIP archive.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode**.
4. Select **Load unpacked** and choose the `teleport-extension` folder (the folder containing `manifest.json`).
5. Pin **IP-Teleport** from Chrome’s Extensions menu if you want quick access.

To update a local copy, replace its files and select **Reload** on the extension card at `chrome://extensions`.

## Permissions

The extension manifest requests `tabs`, `activeTab`, and `storage`, and declares `<all_urls>` host access. Review `teleport-extension/manifest.json` and the source code before installation. Grant broad host access only if it is appropriate for your authorized testing environment.

## Screenshots

<p align="center">
  <em>Product screenshots coming soon.</em>
</p>

## Responsible use

- Define and document the authorized scope before testing.
- Prefer a lab, staging environment, or synthetic data for demonstrations.
- Do not use findings to access, disrupt, or expose systems.
- Report potential vulnerabilities privately to the asset owner and allow reasonable time for remediation.

## License

This project is distributed under the Apache License 2.0. See [`LICENSE`](LICENSE) for details.
