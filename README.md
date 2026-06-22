<p align="center">
  <img src="şəkil_linki_buraya.png" width="200" alt="TripleS Logo">
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

## 📌 Haqqında

**TripleS** komandası olaraq hazırladığımız bu repozitoriya SIEM platformaları (Splunk, QRadar və s.) üçün təhlükəsizlik qaydaları, parserlər və aşkarlama mexanizmlərini bir araya gətirir. Məqsədimiz təhlükəsizlik insidentlərini daha sürətli və effektiv şəkildə aşkar etməkdir.

---

## 📂 Qovluq Strukturu

Repomuz fərqli SIEM sistemləri üzrə səliqəli şəkildə bölünmüşdür:

```text
SIEM-Rules/
├── Splunk/        # Splunk üçün SIEM qaydaları və konfiqurasiyalar
└── QRadar/        # QRadar üçün AQL qaydaları və log mənbələri
