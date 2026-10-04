# ADR-47 — Media efemeră și „vezi o singură dată” (precizează ADR-27 punctele 10 și 12)

| Câmp | Valoare |
|---|---|
| Status | **Aprobat** 2026-10-04 de proprietar (propus 2026-09-25; designul Fazei 11 aprobat cu întrebarea Q1; revizuit 2026-10-04 după dovezile S0) |
| Sursă | ADR-27, ADR-32; FR-7.15; LIMITE:136 |
| Modifică | nimic aprobat; precizează ordinea ștergerii cheii, checkpoint-ul și semantica la crash; citește ADR-27 punctul 12 („se decriptează doar în memorie la afișare”) ca „nimic nu se expune înainte de afișare” (validarea decriptează în memoria nativă înainte, Q11); designul Fazei 9 §10.3 (pentru mesajele media, numărătoarea expeditorului pornește la sfârșitul încărcării, nu la commit) |

## Decizie
1. Media urmează mesajul: în tranzacția SWEEP care șterge mesajul se șterg și rândurile obiectului, inclusiv cheia învelită; după **orice** tranzacție care șterge sau anulează o cheie învelită urmează un checkpoint WAL `TRUNCATE` (busy = 0, trei reîncercări), ca vechea pagină să nu rămână în WAL sau în fișierul bazei; fișierele de ciphertext se șterg după commit (reconciliere), doar dacă niciun alt obiect nu le mai numește. Expeditorul păstrează copia proprie cât trăiește mesajul lui, a cărui numărătoare pornește la sfârșitul încărcării (cel târziu la termen).
2. Releele oneste șterg fragmentele până la `ora-termen + treaptă + 1 h`; fragmentele expiră cel târziu odată cu descriptorul.
3. „Vezi o singură dată” (P1): fără previzualizare; la deschidere, într-o singură tranzacție, cheia trece într-un cititor nativ și se șterge din baza de date, iar checkpoint-ul WAL rulează **înainte** de afișarea oricărui octet; un crash după commit pierde elementul, dar nu permite niciodată o a doua afișare; la închidere se șterg fragmentele. Expeditorul nu păstrează o copie care poate fi revăzută după ce descriptorul are un rezultat final (SENT, DEGRADED sau INDETERMINATE după retrimiteri; la FAILED, la termen); până atunci (în timpul încărcării și după un FAILED) cheia și fișierele lui există. Nu se poate redirecționa. Validarea completă de dinaintea afișării decriptează obiectul, bucată cu bucată, doar în memoria nativă; nimic nu se expune înainte de afișare.
4. Limite declarate: FLAG_SECURE oprește capturile de ecran, nu un al doilea dispozitiv sau o cameră, un client modificat ori un telefon cu root; copiile de pe relee rămân până la TTL; înainte de deschidere, un dispozitiv confiscat conține cheia (învelită); dacă checkpoint-ul rămâne ocupat, vechea pagină trăiește până la următorul checkpoint reușit; originalul rămâne în galeria expeditorului; pixelii pot rămâne în memoria pe care GHOST n-o deține (tablouri JVM eliberate, buffere GPU și ale compozitorului) până la reutilizare.

## Teste
T25 pentru media (logic și fizic, inclusiv scanarea brută a bazei și a WAL-ului imediat după deschidere), SCN-MD (cel mult o afișare la orice punct de crash), SCN-ME, verificarea de confiscare; mutanții MC-M6, MC-M7, MC-M19, MC-M20, PM-M8.
