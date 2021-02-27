# Septembar1 2019

## Uporediti paketnu obradu, multiprogramiranje i multitasking
- paketna obrada je omogućila da se programi nadovezuju jedan na drugi tj. da
  se tokom izvršanja jednog programa učitava drugi.
- sa napredovanjem računara, dolazilo je do velike razlike u brzini rada
  procesora i perifernih uredjaja, gde je procesor znatno brže radio.
- dosta bi se vremena gubilo dok bi proces čekao unos ili odgovor sa
  ulazno-izlaznih uredjaja.
- rešenje ovome je multiprogramiranje, koje je dozvolilo da se memorija podeli
  na particije i da se u svaku upiše program.
- programi bi se smenjivali za rad na procesoru, a dok se neki procesi
  izvršavaju, drugi bi izvršavali ulazno-izlazne operacije.
- multitasking je veoma sličan ideji multiprogramiranje po tome što se isto
  zasniva na smenjivanju procesa koji rade na procesoru, samo sto je kod
  multitaskinga jedinica izvršavanja na procesoru posao (task) koji ne mora da
  bude vezan za izvršavanje ulazno-izlaznih operacija

## Lamportov (pekarski) algoritam
- Lamportov algoritam je uopštenje [Pitersonovog algoritma](Pitersonov algoritam) za n procesa.
- zasniva se na ideji opsluživanja mušterija u pekari, tako da svaki novi
  proces dobija sledeći najveći broj, a na redu je onaj sa najmanjim brojem.
- ne može da se garantuje da dva procesa neće imati isti broj, jer se dodela
  brojeva vrši u kritičnoj sekciji, pa onaj sa manjim indeksom ima prednost.

Lamportov algoritam:
	Proces i:
		uzima[i] = 1; // blokira dok proces uzima broj
		broj[i] = max(broj[0]...broj[n-1]) + 1; // strogo veci od najveceg pret.
		uzima[i] = 0;

		for (j = 0; j < n; j++){
			while (uzima[j] == 1) // ako neki proces koji je ispred i-tog u
				// cekanje           redu uzima broj, i-ti ulazi u aktivno
									 cekanje
			while (broj[j] != 0 AND (broj[j], j) < (broj[i], i))
				// cekanje da proces koji ima prednost dobije broj
		}

		// KRITICNA SEKCIJA //
		broj[i] = 0;

	Svaki proces pri pokretanju uzima broj, što je zaštićeno prom. uzima, pri
	tome da je taj broj strogo veći od najvećeg broja koji je do tad bili,
	znači sad on ima najveći broj od svih procesa.

	Prolazi se kroz sve procese koji imaju viši prioritet od i-tog i ako je
	neki od njih u procesu uzimanja broja, i-ti se blokira dok svaki od
	njih ne završi.

	Zatim, ako j-ti proces ima prednost, i-ti proces čeka da on završi sa
	pristupom kritičnoj sekciji i tek onda može da joj pristupi.

	Proces j ima prednost nad procesom i ako je broj[j] < broj[i], ili, ako su
	broj[j] == broj[i], onda ako je j < i.

## Načini da se otkloni čekanje i držanje. Uslovi da bi došlo do zaglavljivanja.
- situacija gde dva ili više procesa čeka na resurse koji se nikad neće
  osloboditi je **zaglavljivanje**.
- da bi došlo do zaglavljivanja neophodno je da se u sistemu ispune sva 4 uslova:
	- **Uzajamno isključenje (Mutual Exclusion)** - u jednom trenutku samo
	  jedan proces može da koristi neki resurs
	- **Čekanje i držanje** - proces drži neke resurse, a u isto vreme zahteva
	  neke druge
	- **Nemogućnost prekidanja** - operativni sistem nema pravo da procesu
	  oduzme resurse koje mu je dodelio.
	- **Kružno čekanje** - da jedan proces drži neke resurse, a čeka na resurse
	  koje drži drugi proces, koji čeka da se oslobode resursi prvog procesa.

	Ova 4 uslova se često nazivaju **Kofmanovi uslovi**.

- **Prevencija čekanja i držanja** se zasniva na uvodjenju ograničenja da
  proces drži neke resurse dok zahteva nove.
- jedan pristup je da proces ne udje u izvršavanje dok ne dobije sve resurse
  koji su mu potrebni.
- mana ovog pristupa je da će proces držati sve potrebne resurse i time da
  spreči druge procese da ih koriste, u trenucima kad mu nisu potrebni.
- takodje, teško je znati na početku koji će svi resursi biti potrebni.
- drugi pristup podrazumeva da proces, kad traži nove resurse od sistema, mora
  prvo da vrati resurse koje drži.
- kad vrati resurse operativnom sistemu, on onda odlučuje da li će ih ponovo
  dodeliti njemu ili nekom drugom procesu.

## Objasniti i uporediti statičke i dinamičke particije
- particije su neprekidni delovi memorije koji ne moraju da budu iste veličina
  u kojima se smeštaju programi.
- postoje dva tipa particionisanja memorije: **statički** i **dinamički**.

### Statičke particije
- memorija se statički deli na fiksi broj particija, u svakoj se nalazi proces.
- kod sistema sa statičkim particijama, procesi koji pristižu se smeštaju u red
  spremnih procesa.
- planer prati memorijske potrebe svakog procesa i slobodne particije i
  odlučuje kom procesu dodeliti koju particiju.
- kad je u pitanju odabir particije, postoje dve strategije.
	- svaka particija ima svoj red poslova koji odgovaraju veličini particije
	- svi procesi su u jednom redu, plener odlučuje koji je sledeći proces
		U ovom slučaju se čeka da se oslobodi particija odgovarajuće veličine.
		Može da se desi da prvi proces u redu ne može da stane u slobodnu
		particiju, ali da neki proces dalje u redu može, pa postoje
		modifikacije koje dozvoljavaju ovakvo preskakanje reda.

### Dinamničke particije
- suprotno od statičkih, kod dinamičkih particija veličina nije fiksna.
- kad se pokrene računar, u memoriju se učita operativni sistem, dok ostatak
  memorije obrazuje jednu veliku particiju.
- sa pokretanjem svakog naredog procesa se prostala slobodna memorija deli na
  dva dela: onaj koji je dodeljen procesu i drugi deo koji ostaje slobodan.
- nakon završetka procesa, on oslobadja memoriju.
- ako se pored oslobodjene memorije nalazi drugi blok slobodne memorije, one se
  spajaju jednu veću slobodnu particiju.
- evidencija o slobodnim i zauzetim particijama vodi operativni sistem, obično
  preko bit-mapa ili povezanih listi.
- Kod bit-mapa, memorija se podeli na jednake delove i pridružuje jedan bit
  koji je 1 ako je zauzet, a 0 ako je slobodan.
- onda se pronalaženje prostora za proces svodi na nalaženje dovoljno dugačke
  serije 0, što može da bude prilično zahtevno, pa se češće koriste povezane
  liste.
- povezana lista se sastoji od čvorova, svaki od kojih sadrži:
	- da li je tu smešten proces ili je slobodan prostor
	- početak tog dela memorije
	- dužina tog dela memorije
	- pokazivač na sledeći čvor
- nekad se liste slobodnih i zauzetih particija implementiraju odvoje, radi
  lakše pretrage.
