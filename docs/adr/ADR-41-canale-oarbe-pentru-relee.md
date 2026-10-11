# ADR-41 — Canale oarbe pentru relee: sigiliu exterior pe epocă, generații, chei comune de citire și depunere, rotație la scoatere, finanțatori

Depus din designul Fazei 10 (`docs/design/faza10-forum.md`, Anexa A) de felia S12 (2026-10-11); sursa normativă rămâne Anexa A.

| Câmp | Valoare |
|---|---|
| Status | **Propus** 2026-09-25, în așteptarea deciziei proprietarului (Q1) |
| Sursă | design Faza 10 §5, §6.5, §7, §8, §19.7, §19.8, §19.9, §19.16, §19.24 |
| Modifică | Anexa B a planului („namespace = H(cheia publică a canalului)”; „capabilitate de citire per epoch”); designul Fazei 8, D11 („per (namespace, epocă)”) și ADR-25 punctul 9; ADR-27 punctul 11 pentru mesajele de administrare ale canalelor cu timer ≤ 1 zi; INVARIANTS T9, T25 |

**Context.** MLS lasă în clar identificatorul grupului, epoca, tipul conținutului și, în Welcome, referințele KeyPackage. Releele nu au logică de grup. Înregistrările `RegisterKey` sunt pe săptămâni și se acumulează, deci nu pot fi revocate la „epoch-ul următor”.

**Decizie.**
1. Fiecare octet al unui canal stocat pe relee e sigilat (`salt ‖ hint ‖ AEAD`, forma DM) sub o cheie de epocă derivată din exportatorul MLS sau sub cheia de intrare a generației; niciun antet MLS nu apare în afara sigiliului.
2. Un canal trece prin generații; secretul generației derivă din exportatorul epocii care a deschis-o; din el derivă namespace-ul, secretele de citire și de depunere per slot și cheia de intrare. O generație nouă începe la fiecare commit care scoate un pseudonim (scoatere, plecare, evacuare) sau restaurează un membru pe un dispozitiv nou (dispozitivul înlocuit e tratat ca scos), schimbă clasa de mărime sau poartă indicatorul de rotație al unui comitent (după expirarea nefolosită a unei invitații a generației sau la 28 de zile, cel mult o dată la 14 zile și niciodată cât se golește o generație veche); cel scos nu poate calcula noua generație. Membrii trec pe namespace-ul nou la ora fixată de commit (sau la următoarea sesiune), nu la minutul în care l-au descărcat; cei scoși continuă să asculte namespace-ul vechi până la golire, ca toți ceilalți. Namespace-ul vechi se golește în 14 zile; cel mult două generații ascultate per canal.
3. Toți membrii depun cu credențialul DEPOSIT al generației și citesc cu credențialul READ (credențiale purtătoare v3, `RegisterKey`, neschimbate); finanțatorii (proprietarul și cel mult doi membri) răscumpără token-uri numai pentru înregistrări, la momentul de reînnoire al Fazei 8; comitentul care a făcut rotația finanțează generația nouă la ora de trecere fixată de propriul commit.
4. Clase de mărime: mic (≤ 32 de membri, treaptă minimă 4 KiB), mare (≤ 100, 16 KiB); treapta unui blob depinde doar de lungime și de clasă; orice commit cu o singură propunere încape în treapta minimă (măsurat în S0 cu pachete de chei canonice, în arbori de până la 128 de frunze: cea mai mică rezervă 172 de octeți), iar cele cu mai multe propuneri se împart.
5. TTL: postările urmează ADR-27 punctul 11; mesajele de administrare folosesc același TTL în canalele cu timer de 7 zile, 30 de zile sau dezactivat și 7 zile în canalele cu timer ≤ 1 zi (abatere declarată).
6. Nicio modificare a releului și niciun câmp observabil nou.
7. Mesajele administrative `INVITE_ISSUED` și `LEAVE` folosesc TTL-ul mesajelor de administrare (în canalele cu timer ≤ 1 zi, 7 zile), fiindcă comitenții au nevoie de ele zile întregi.
8. Media în canale (spec FR-3.4) folosește contractul Fazei 11, rezervat de acum în formate: TLV-ul 0x0003 poartă cei 84 de octeți ficși ai descriptorului, textul postării e legenda, cheia fișierului intră și iese din slot doar în Rust; namespace-ul de media, costul lui și testele de acceptare vin cu felia de media a canalelor (Q38).

**Consecințe.** (+) Releele nu leagă nimic de pseudonime sau de identificatorul canalului; un singur scop de depunere și unul de citire per releu și namespace; un membru scos nu mai vede nimic din generația nouă; commit-urile arată ca postările în canalele implicite; rotațiile de rutină ascund momentul scoaterilor. (−) 3 token-uri pe săptămână per canal per finanțator și 3 la fiecare rotație; releele văd rotațiile și intrările (co-apariția le leagă sub AD-1) și pot recunoaște rolurile: finanțatorii (implicit proprietarul), comitentul care rotește, membrul scos (LC-8); o invitație scursă dă intrarea în canal și acces la metadatele generației până la rotație; orice membru poate epuiza cota săptămânală; cel mult 9 canale per client (bugetul de 64 de perechi de citire, depășibil în cele șase săptămâni de după o schimbare a tabelului de sloturi); după mutarea unui slot, operatorul plecat poate folosi secretele văzute până la rotație.

**Alternative respinse.** MLS brut pe relee; o cheie de sigilare statică per canal; namespace pe viața canalului; namespace per epocă; capabilități de scriere per membru; token-uri de rată per membru (P2).

**Teste.** T36, T37, T38; JC-1 … JC-5, JC-7; NI-CH2, NI-CH3, NI-CH4; oracolul membrului scos (și varianta restaurării); PC-1 … PC-4, PC-7, PC-8, PC-10, PC-11, PC-13, PC-15 … PC-17; MM-7, MM-8, MM-29.
