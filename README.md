# GHOST

Forum și messenger Android proiectat astfel încât operatorul să nu poată citi conținutul, să nu cunoască identitatea, IP-ul sau plata utilizatorilor.

**Stadiu: developer preview. Nicio afirmație de confidențialitate nu este încă validată.** Vezi [docs/STATUS.md](docs/STATUS.md).

| Unde | Ce |
|---|---|
| [docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md](docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md) | Planul de implementare (delta peste spec v2.0) |
| [docs/adr/](docs/adr/README.md) | Decizii de arhitectură (ADR-01…16 aprobate) |
| [docs/THREAT_MODEL_v2.1.md](docs/THREAT_MODEL_v2.1.md) | Threat model: active, adversari, granițe, scenarii, invarianți |
| [docs/LIMITE_REZIDUALE_SI_MITIGARI.md](docs/LIMITE_REZIDUALE_SI_MITIGARI.md) | Ce nu poate fi garantat și cum se reduce paguba |
| [output/pdf/](output/pdf/) | Specificația tehnică v2.0 FINAL |
| [ghost/](ghost/README.md) | Codul activ: client Android, relay și issuer (Rust), scheme de protocol, gate-uri CI |
| [legacy/](legacy/README.md) | Prototipuri în carantină; nu se reutilizează |

Build și reguli de contribuție: [ghost/docs/DEVELOPMENT.md](ghost/docs/DEVELOPMENT.md).
