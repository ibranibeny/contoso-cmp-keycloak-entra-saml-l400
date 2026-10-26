# Contoso CMP Identity — Keycloak × Microsoft Entra ID (SAML 2.0) · L400

Static GitHub Pages site documenting how Contoso's Cloud Management Platform (CMP) signs people in with **Keycloak** (OpenID Connect) and how a separate **SAML 2.0** trust lets **Microsoft Entra ID** admit them to Azure as **B2B guests** (Domainless SAML/WS-Fed identity provider).

* Start page: `index.html`
* Concepts: SAML 2.0, Microsoft Entra ID & B2B, Keycloak, end-to-end flows
* Architecture: deployed PoC topology with official Azure Architecture Icons and a Well-Architected review (page 5); Azure landing zone target architecture — management groups, hub-and-spoke, Application Gateway WAF, private endpoints, PIM (page 5b); pillar-by-pillar Well-Architected alignment with an operations, monitoring and governance diagram, failure-mode analysis and trade-offs (page 5c)
* Guides G1–G9: deploy, configure Keycloak, export metadata, Entra Domainless IdP, guests & RBAC, users, CMP app, end-to-end test, operations — each with scripts and screenshots
* `scripts/`: sanitized scripts and templates from the PoC

## Honesty conventions
* **PoC capture · sanitized** — real browser captures; only identifiers were replaced with Contoso sample values.
* **Illustrative · rendered** — rendered from the scripts/configuration (console output shape, recreated admin screen, expected SAML message). Not a live capture.
* **PoC item** — undocumented or not yet demonstrated behaviour. Azure portal SSO through the SAML trust is **not yet proven** (see `15-poc-evidence-backlog.html`).

Contoso is a fictitious company. Not official Microsoft documentation.

## Publish
GitHub Pages: deploy from branch `main`, folder `/ (root)`. See `publish-to-github-pages.ps1`.
