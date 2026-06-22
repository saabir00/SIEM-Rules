<p align="center">
  <img src="images/image_2026-06-22_222753191.png" width="200" alt="TripleS Logo">
</p>

<h1 align="center">🛡️ SIEM-Rules - TripleS</h1>

<p align="center">
  <em>Mərkəzləşdirilmiş SIEM mühitləri üçün təhlükəsizlik qaydalarının (rules) və konfiqurasiyaların idarə edilməsi.</em>
</p>

<p align="center">
  <a href="#haqqında">Haqqında</a> •
  <a href="#struktur">Qovluq Strukturu</a> •
  <a href="#komanda">Komandamız</a>
</p>

---


## 📂 Qovluq Strukturu

Repomuz fərqli SIEM sistemləri üzrə səliqəli şəkildə bölünmüşdür:

```text
SIEM-Rules/
├── QRadar/
│   ├── rules/       # QRadar üçün AQL qaydaları, building blocks və ya XML faylları
│   └── scripts/     # API skriptləri, avtomatlaşdırma və ya log göndərmə vasitələri
└── Splunk/
    ├── rules/       # Splunk üçün SPL axtarışları, Saved Searches və ya Detection Rules
    └── scripts/     # Splunk üçün HEC skriptləri, Inputs və ya Təhlil alətləri
