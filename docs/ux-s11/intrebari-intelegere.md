# S11 — banca de întrebări de înțelegere (post-călătorie)

Prag: **≥ 7/8 corecte per participant** (decizia proprietarului Q42, 2026-10-20). Fiecare călătorie are
8 întrebări din banca ei (cele marcate ◆ sunt cele din exemplele designului §12.5); facilitatorul
notează răspunsul verbatim și îl evaluează după cheia de mai jos. Întrebările nu se reformulează cu
indicii; un „nu știu" se notează ca greșit, fără presiune.

## J1 (onboarding + cuvinte)
1. ◆ Cine îți vede adresa IP când folosești aplicația? (Așteptat: releele/nimeni din afara circuitului Tor; nu corespondentul, nu operatorul cu totul.)
2. ◆ Ce se întâmplă dacă pierzi telefonul? (Așteptat: cuvintele de pe hârtie restaurează identitatea; fără ele, datele sunt pierdute definitiv.)
3. De ce ți se cere PIN-ul înainte să vezi cuvintele a doua oară? (Așteptat: cine are telefonul deblocat nu e automat posesorul; biometria poate fi forțată.)
4. Ce faci cu cele 24 de cuvinte concret, în prima zi? (Așteptat: le notezi pe hârtie, le păstrezi offline; nu le copiezi, nu le fotografiezi.)
5. Cine poate citi mesajele tale — când rulează aplicația vs. cu telefonul blocat? (Așteptat: criptate pe disc; ecranul blocat nu compune nimic cu conținut.)
6. Ce verifică provocarea cu pozițiile după ce ai notat cuvintele? (Așteptat: că le-ai copiat corect; la greșire se reia cu pozițiile ratate.)
7. Ce pierzi la restaurare pe un telefon nou? (Așteptat: mesajele vechi/canalele locale rămân pe vechiul dispozitiv; identitatea și contactele continuă.)
8. Ce alegi la modul de confidențialitate ridicat și ce schimbă? (Așteptat: întârzieri până la 10 min, citiri mai rare; traficul rămâne vizibil ca volum.)

## J2 (acces și plată)
1. ◆ Cine vede că ai plătit și ce anume? (Așteptat: issuer-ul vede suma uniformă și momentul, fără expeditor; rețeaua Monero vede o tranzacție opacă.)
2. De ce plata nu apare instant? (Așteptat: confirmările în rețea durează de la minute la ore.)
3. De ce se compară primele și ultimele 6 caractere ale adresei după copiere? (Așteptat: tastatura sau clipboard-ul pot înlocui adresa.)
4. Ce se întâmplă dacă trimiți mai puțin? (Așteptat: subplată — se poate completa în fereastra de 24 h.)
5. Plătitul de pe exchange cu KYC ce expune? (Așteptat: exchange-ul te leagă de plata către subadresă.)
6. Ce se oprește cât e ecranul de plată deschis? (Așteptat: sincronizarea, 20–60 min după.)
7. Cine decide prețul și cât de anonim e? (Așteptat: suma uniformă per epocă — toată lumea plătește la fel.)
8. Cere-i participantului să indice pe ecran unde a văzut termenul limită. (Așteptat: îl găsește neghidat.)

## J3 (contact și siguranță)
1. ◆ Ce înseamnă „Trimis"? (Așteptat: mesajul a plecat spre releu; nu înseamnă citit.)
2. ◆ Unde ai văzut acest cod prima dată — și ce schimbă răspunsul? (Așteptat: „pe telefonul persoanei, în fața mea" = calea verificată; altfel = link neverificat + comparație de număr.)
3. ◆ Ce poate face cine are cardul tău? (Așteptat: îți poate scrie pentru totdeauna; primul mesaj îi dă cardul întreg — de aceea proveniența contează.)
4. Ce verifică numărul de siguranță? (Așteptat: că nimeni nu a înlocuit cheile pe drum; se compară în persoană.)
5. Ce se întâmplă la schimbarea de cheie a contactului? (Așteptat: banner în aplicație; mesajele reținute așteaptă decizia; nicio notificare de sistem.)
6. Ce vede celălalt despre tine? (Așteptat: identitatea de bază din canalul DM, conținutul, numărul de siguranță; nu IP, nu canalele tale.)
7. Ce face blocarea — și ce NU face? (Așteptat: locală; depunerile mai vin și se resping; contactul nu află.)
8. Minutele mesajelor de ce sunt vizibile celuilalt? (Așteptat: precizia de minut e parte din protocol; nu poți alege.)

## J4 (canalul cu parolă)
1. Cine te vede când intri într-un canal? (Așteptat: pseudonimul din canal; moderatorul vede cererea; identitatea de bază rămâne ascunsă fără dezvăluire.)
2. ◆ De ce se compară amprenta și numărul epocii înainte să postezi? (Așteptat: la aceeași epocă, coduri diferite = copie falsă a canalului; epoci diferite = compară mai târziu.)
3. Cine știe parola canalului? (Așteptat: fiecare membru — și fiecare membru scos; de aceea se schimbă după o scoatere.)
4. De ce nu există buton de copiere pentru frază-parolă? (Așteptat: se comunică în persoană, pe hârtie.)
5. Ce se întâmplă după ce ceri să intri? (Așteptat: aștepți aprobarea unui moderator; poate dura ore.)
6. Același pseudonim pe două canale — ce înseamnă? (Așteptat: e același identificator — de aceea canalele nu te de-anonimizează între ele.)
7. Ce poate demonstra cine i-ai dezvăluit identitatea? (Așteptat: oricui, oricând, că pseudonimul ești tu — de aceea dezvăluirea e ireversibilă și se confirmă prin comparație la aceeași epocă.)
8. Cine poate invita în acest canal? (Așteptat: doar comitenții — regula canalelor cu parolă.)

## J5 (media)
1. Ce se întâmplă cu originalul fotografiei pe telefonul tău? (Așteptat: rămâne în galerie; trimisă e re-codată.)
2. „Vezi o dată" — ce garantează și ce nu? (Așteptat: o deschidere pe acest telefon, cheia ștearsă la deschidere; NU oprește fotografierea ecranului cu alt telefon.)
3. Ce vede un străin dacă primește telefonul cu aplicația blocată? (Așteptat: nimic — ecranul de blocare nu compune conținut; notificarea nu are conținut.)
4. De ce trimiterea poate dura ore? (Așteptat: se face pe rând, în fundal, la pasul de sincronizare.)
5. Ce faci când o descărcare a eșuat? (Așteptat: reîncerci din ecranul obiectului — limitat, înainte de termen.)

## J6 (versiunea)
1. Unde găsești versiunea? (Așteptat: Setări → Despre.)
2. Cine vede când verifici actualizările? (Așteptat: oglinzile de actualizare — apare în „Cine vede ce".)
3. De ce nu există „verifică această aplicație" în interiorul ei? (Așteptat: o aplicație compromisă ar raporta ce vrea; verificarea se face din afară, cu ghost-verify.)
4. Ce înseamnă „informațiile despre versiuni au N zile"? (Așteptat: vârsta manifestului — date publice, fără ora dispozitivului.)

## Cheia de evaluare
- Corect = esența răspunsului coincide cu așteptatul, în cuvintele participantului.
- Parțial = jumătatea esenței; se notează, nu se punctează.
- Greșit/nu știu = restul.
- Un răspuns care citește textul de pe ecran la întrebarea potrivită se punctează corect — asta înseamnă că textul și-a făcut treaba.
