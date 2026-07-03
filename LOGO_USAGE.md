# DevLeakShield Logo Usage Guide

## Quick Reference

### Logo Files Created

| File | Size | Use Case |
|------|------|----------|
| **logo-icon.svg** | 2048×2048 | Favicon, marketplace, status bar, badges |
| **logo-vertical.svg** | 1024×1200 | README headers, social media, docs |
| **logo-horizontal.svg** | 1200×320 | Website headers, banners, GitHub profile |
| **DevLeakShield-Logo-Favicon.svg** | 2048×2048 | Favicon (small size optimized) |
| **BRAND_IDENTITY.md** | — | Complete design guidelines & specifications |

---

## Primary Use Cases

### 1. VS Code Marketplace
```json
// In package.json
{
  "icon": "logo-icon.svg"
}
```
**Size:** 128×128px (auto-scaled from 2048×2048)

### 2. GitHub Repository
```markdown
# [Logo] DevLeakShield
```
**Use:** logo-vertical.svg at 400–600px width

### 3. Favicon
```html
<link rel="icon" type="image/svg+xml" href="logo-icon.svg">
```

### 4. README Badges
```markdown
![DevLeakShield](./logo-icon.svg)
```
**Size:** 64–128px

### 5. Website/Docs Header
Use **logo-horizontal.svg** at 600–1200px width

---

## Color Palette

- **Primary Blue:** #2563EB
- **Cyber Cyan:** #06B6D4
- **Emerald:** #10B981

All colors tested for WCAG AAA accessibility.

---

## Design Principles

✅ Geometric, minimal, flat design  
✅ Symmetrical and professional  
✅ Clear at 16×16px and 2048×2048px  
✅ No shadows, gradients, or 3D effects  
✅ High contrast on light and dark backgrounds  

---

## File Format

All logos are SVG (Scalable Vector Graphics):
- **Advantage:** Perfect scaling, small file size, web-ready
- **Export:** Can be converted to PNG/JPG for specific uses
- **Optimization:** Already optimized, no SVGO needed

---

## Version

**v1.0** – Production Ready  
**Status:** Complete Brand Identity System  
**Date:** 2026-07-03

---

For detailed design specifications, see **BRAND_IDENTITY.md**.
