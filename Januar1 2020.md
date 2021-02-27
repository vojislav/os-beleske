# Januar1 2020

## 1. Hardverska rešenja kritične sekcije. Primeri.
- podrazumevaju upotrebu posebnih instrukcija procesora.
- to su instrukcije koje mogu bar dve operacije da izvrše **atomično** tj. da
  ne mogu prekinute u sred.
- najčešće instrukcije za zaštitu kritične sekcije su:
	- **TAS (Test And Set)**
	- **FAA (Fetch And Add)**
	- **SWAP (zamena)**
- **TAS** uzima dve promenljive, **A = TAS(B)**, gde A dobija vrednost B, a B
  se postavlja na 1.
- **FAA** takodje uzima dve promenljive, **FAA(A,B)**, gde A dobije vrednost B,
  a B dobija vrednost A+B (stara vrednost A, pre promene vrednosti).
- **SWAP** atomično zamenjuje vrednost dveju promenljivih A i B.
- Za hardversko rešenje korišćenjem TAS, pogledati [Januar1 2021](Januar1 2021).

Zaštita kritične sekcije pomoću SWAP

	Procesi i:
		kljuc = 1;
		WHILE (kljuc != 0)
			SWAP(brava, kljuc);

		// KRITICNA SEKCIJA //
		brava = 0;

- svaki proces krene od toga da im je ključ = 1
- ako je brava = 1 znači da je zaključana, i sve dok je zaključana procesi će
  čekati u svojoj petlji da neki proces izadje iz svoje kritične sekcije i
  otključa bravu tj. da je postavi na 0 i time da priliku da neki drugi proces
  udje u kritičnu sekciju.

## 2. Virtuelna memorija i straničenje na zahtev
- način da se procesu da na raspologanje memorija koja je veća nego ona koja
  stvarno postoji na sistemu u tom trenutku.
- operativni sistem je zadužen za preslikavanje ove memorije u fizičku
- prve implementacije virtuelne memorije su podrazumevale da se radna memorija
  podeli na manje delove u koje bi se smestili procesi, dok je na savremenim
  sistemima vezano za tehniku koja omogućuje da se izvršava proces koji nije
  potpuno u radnoj memoriji.
- ovim se omogućava veći stepen multiprogramiranja, jer može da se izvršava
  proces koji nije potpuno u radnoj memoriji, a i tadkodje da procesi mogu da
  budu veći od fizičke radne memorije (opet, jer se ne učitava ceo)

- najpopularniji način implementacije virtuelne memorije je
  **straničenje na zahtev (Demand Paging)**.
- kao i kod straničenja, ovde se program deli na stranice i prilikom pokretanja
  programa se u radnu memoriju smeštaju samo one stranice koje su neophodne za
  u prvom trenutku.
- kada se neka stranica zatraži tokom izvršavanja procesa, prvo se gleda da li
  je već učitana u memoriji, a ako nije učitava se iz sekundarne memorije.
- slično kao i straničenju, i ovde postoji tabela stranica koja čuva adrese
  okvira, ali pored toga ima i kolona koja drži **bit validnosti**, koji je 1
  ako je stranica učitana u memoriju, a 0 ako nije.
- kada proces pokuša da učita stranicu, proverava se ovaj bit i ako je on
  uključen onda joj se odmah može pristupiti, dok ako nije dolazi do
  **promašaja strnice (page fault)** i sledi prekid, nakon čega se potreba
  stranica donosi u memoriju.
- stranica se učitava u slobodan memorijski okvir, dok ako ih nema, oslobadja
  se neki od zauzetih okvira, i menja se njen bit validnosti.

- izbacivanje stranice kad nema slobodnih okvira poteže pitanje kojim
  kriterijumom se bira stranica za izbacivanje tj. **žrtva**.
- postoji nekoliko algoritama za biranje žrtve:
	- **Slučajno izbacivanje**

		Nasumično se bira stranica za izbacivanje. Nije dobar algoritam jer može da
		dovede do izbacivanja nekih važnih stranica što povećava broj promašaja.
	- **Beladijev optimalni algoritam**

		Izbacuje se ona stranica koje će najkasnije u budućnosti biti potrebna i
		time se smanjuje broj promašaja. Najveći problem ovog pristupa je što je
		skoro nemoguće implementirati tj. teško je znati koja stranica će kad biti
		potrebna u budućnosti.
	- **FIFO algoritam**

		Iz memorije se izbacuju stranice koje su prve došle u memorije. Mana
		kod ovog pristupa je što se obično važne stranice učitavaju na početku,
		a ovom metodom bi se one prve izbacile. Takodje bi moralo da se pamti
		vreme kad je stranica ubačena u memoriju i onda stalo da se sortiraju
		ta vremena, što i vremenski i prostorno zahtevno. Češća implementacija
		FIFO algoritma koristi povezanu listu. Stranice se dodaju na kraj, a
		dodaju na početak.


	- **Algoritam druge šanse**

		Zasniva se na tome da se pored stranice učitane u memoriji, stavlja i
		**bit referisanosti (R)** koji se postavlja na 1 kad se stranica učita
		u memoriju. Pretraga za žrtvu kreće od prve učitane stranice, ako je
		njen bit referisanost 1, postavlja se na 0 i pomera na kraj liste, tako
		se tretira kao da je poslednje učitana. Kad se naidje na stranicu čiji
		je bit jednak 0, ona se izbacuje. Time se svakoj stranici daje druga
		šansa. Problem se javlja kad je bit svake stranice 1, jer će onda svaki
		biti 0, i prva će biti izbačena prva učitana stranica.

	- **Algoritam sata**

		Nadovezuje se na prošli algoritam, samo umesto povezane liste, koristi
		se kružno povezana lista. Koristi se jedan kružni pokazivač koji kreće
		od prvog okvira i svaka stranica opet ima bit referisanosti. Opet se
		javlja problem kad su svi bitovi referisanosti 1.

	- **LRU (Least Recently Used)**

		Izbacuje se algoritam koji je najdalje u prošlosti korišćen. Zasniva se
		na pretpostavci da su stranice koje su skoro korišćene važne i da
		uskoro opet biti korišćene. Opet zahteva registar sa vremenom
		učitavanja koje je potrebno sortirati što je zahtevno.

	- **NRU (Not Recently Used)**

		Izbacuje se stranica koje nije skoro korišćena, ali ne nužno najduže
		nekorišćena. Opet se koristi bit referisanost, ali da bi se izbegao
		slučaj da su svi bitovi jednaki dodaje se periodično resetovanje
		bitova. Biranje periode resetovanje nije jednostavno.

	- **Modifikacija NRU algoritma**

		Podrazumeva dodavanje bita modifikacije na prošli algoritam, postavlja
		se na 0 pri učitavanju, a na 1 pri menjanju stranice.

		Sa bitom referisanosti i bitom modifikacije moguće su sledeće
		kombinacije:
			1. nije referisana ni modifikovana     - 00
			2. nije referisana, a modifikovana je  - 01
			3. jeste referisana, nije modifikovana - 10
			4. jeste referisana i modifikovana     - 11

		Ovo takodje predstavlja redosled za optimalno izbacivanje.
		Kombinacija 2. se čini nemogućom, ali imati na umu da nakom isteka
		periode resetuju samo bitovi referisanosti, dok bit modifikacije ostaje
		isti.

	- **LFU i MFU (Least i Most Frequently Used) algoritmi**

		**LFU** - izbacuje se najmanje često korišćana stranica. Opet, vodjenje računa o
		frekvenciji korišćenja zahteva praćenje vreme pristupanja i stalno
		sortiranje, pa je zahtevno. Još jedna velika mana je loš tretman
		stranica koje su tek ušle u sistem tj. stanice koji nikad nisu (imale
		priliku da budu) korišćene, pa se prve izbacuju. Takodje kod stranica
		koje se veoma često koriste u jednom periodu dok u drugom skoro uopšte
		ne. One će ostati u sistemu, čak iako nisu potrebne.

		**MFU** - suprotno, izbacuju se najviše korišćene stranice. Dolazi do
		izbacivanja veoma važnih stranica koje su često i veoma važne.

## 3. Detaljno opisati načine implementacije fajlova
- svaka memorija ima najmanju jedinicu prostora koja može biti alocirana i
  adresirana, **blok**.
- veličina bloka zavisi od diska, obično je 512 bajta ili 4 kilobajta.
- svaki kreirani fajl je u memoriji predstavljen kao skup blokova.
- postoji nekoliko načina organizovanja blokova koji pripadaju fajlu i
  alociranju slobodnih blokova

### Neprekidna alokacija
- svaki fajl se čuva kao neprekidni niz blokova u memoriji
- fajlovi se sekvencijalno smeštaju u memoriji, nakon poslednjeg bloka
  prethodnog fajla.
- moguć je i direktan pristup svakom delu fajla, samo je potreban početni blok
  fajla. Direktorijumi takodje za fajlove samo čuvaju početni blok i koliko
  blokova fajl zauzima.
- problem je što pri brisanju fajlova dolazi do fragmentacije
- kad se fajl obriše, na njegovom mestu ostaje slobodan prostor koji može da se
  popuni fajlovima, ali može da se desi da sistem ima dovoljno slobodnog
  prostora, ali nijedan neprekidni niz slobodnih blokova dovoljno velikih za
  novi fajl.
- interna fragmentacija je takodje problem, jer će skoro uvek ostati više
  slobodnog mesta na kraju poslednjeg bloka (male su šanse da neki fajl zauzima
  ceo broj blokova)
- još veći problem leži u tome da je nemoguće pretpostaviti koliko će fajl
  rasti u budućnosti i samim tim, koliko prostora nakon njega takodje treba da
  bude slobodno.

### Povezane liste
- umesto da fajl bude niz blokova u memoriji, može da bude povezana lista
  blokova, gde svaki blok drži adresu sledećeg bloka.
- direktorijumi samo moraju da drže adrese prvog bloka fajlova, dok će
  poslednji imati referencu na neku null vrednost da ozači da je poslednji.
- očigledna je prednost da blokovi fajla mogu biti razbacani po disku, jer onda
  fajlovi mogu da rastu sve dok ima slobodnog mesta.
- problem povezanih lista dolazi kada je potreban direktan pristup delu fajla,
  svaki put mora da se krene od početka.

### Indeksirana alokcija
- svaki fajl sadrži **blok indeks** koji sadrži fiksan broj adresa svih
  blokova koje fajl zauzima u nizu.
- direktorijumi za svaki fajl samo čuvaju adresu blok indeksa fajla.
- direktan pristup je moguć čitanjem i-tog bloka u blok indeksu.
- kako fajl raste, nove adrese blokova se samo dodaju na kraj niza adresa.
- mana je što se više prostora troši na pokazivače, za fajl koji sadrži samo
  nekoliko bloka, za čuvanje tih nekoliko adresa se alocira ceo blok indeks.
- takodje je problem ako blok indeks nije dovoljno velik da sadrži adrese za
  sve blokove fajla.
- za rešavanje ovih problema postoji nekoliko mehanizama:
	- **Povezana lista blokova**

		Kad ponestane mesta u blok indeksu za sve adrese, poslednje adresa blok
		indeksa pokazuje na drugi blok indeks koji drži adrese ostalih blokova.
		Mali fajlovi imaju jedan blok indeks, dok veliki imaju više.

	- **Indeksi sa više nivoa**

		Indeks sa dva nivoa ne sadrži adrese blokova, već adrese drugih indeks
		blokova	koji sadrže adrese blokova. Da bi se pristupilo bloku, prvo se pristupa
		indeks bloku, pa tek u njemu adresi samog bloka.

	- **Hibridni pristup**

		Mešavina prethodna dva. Odredjen broj blokova na početku pokazuje
		direktno na blokove, nakon toga odredjen broj su indeksi drugog nivoa,
		nakon toga neki broj su indeksi trećeg nivoa itd.


### Monitori. Suština, svrha i prednost.
Pogledati [Januar1 2021](Januar1 2021)
