# legacy/ — cod în carantină

Conținutul acestui director **nu este baseline** și **nu se reutilizează** (ADR-10, aprobat 2026-09-10).

| Director | Ce este | De ce e aici |
|---|---|---|
| `ghostforum-app/` | Prototip Android (pachet `com.ghostforum`, Gradle Groovy) | Criptografie simulată (string prefixes, `return true`, XOR), chei derivate din semnături Ethereum, `allowBackup=true`, nu compilează |
| `ghost-forum/` | Al doilea prototip (pachet `com.ghost.forum`, 6 module JVM) | Double Ratchet și „MLS” custom cu MAC/semnături nefuncționale, relay-uri clearnet hardcodate, nu compilează; testele validează cod simulat |

Detalii complete: `docs/GHOST_Master_Plan_v2.1_OPTIMIZAT.md`, §1.

Fișiere eliminate la carantinare: `openjdk-17.zip` (pagină 404), `tmp/gradle-dist/` (distribuție Gradle), `ghost-forum/gradle/wrapper/gradle-wrapper.jar` (132 MB — o distribuție Gradle mascată ca wrapper), `SOLUTION_SUMMARY.md` (contrazicea spec v2.0).

Codul activ trăiește exclusiv în `ghost/`. Gate-urile CI din `scripts/gates/` exclud `legacy/` de la verificări și de la build.
