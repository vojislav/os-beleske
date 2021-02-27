# Januar1 2021

## TAS instrukcija
- hardverska rešenja zaštite kritične sekcije se zasniva na korišćenju posebnih
  instrukcija procesora.
- jedna od njih je TAS (Test And Set) instrukcija, koja uzime dve promenljive,
  **A = TAS(B)** gde A dobija vrednost B, a B se postavlja na 1.
- procesorske instrukcije su **atomične** što znači da ne mogu da budu
  prekinute u sred izvršanja.
- jedan primer zaštite kritične sekcije korišćenje TAS instrukcije je sledeći

	Proces i:
		ne_može = 1;
		WHILE (ne_može = 1)
			ne_može = TAS(zauzeto)
		ENDWHILE
		// KRITIČNA SEKCIJA //
		zauzeto = 0;

- ne_može se na početku postavlja na jedan i onda se ulazi u petlju koja će se
  izvršavati sve dok je zauzeto = 1 (ako je zauzeto = 1, sa TAS ne_može dobija
  vrednost 1, a zauzeto ostaje nepromenjeno i time se ostaje u petlji)
- kad kritična sekcija ne bude više zauzeta, tako što neki proces završi rad u
  njoj i postavi zauzeto na 0, to daje priliku sledećem procesu da izadje iz
  svoje petlje i da udje u svoju kritičnu sekciju (kad je zauzeto = 0, preko
  TAS ne_može postaje 0, čime se izlazi iz petlje, a zauzeto opet postaje 1,
  čime se opet blokira kritična sekcija)
- mana ovog pristupa je da je zasnovano na hardverskoj podršci, mora procesor
  da ima ugradjenu tu instrukciju.
- takodje, može da dodje do "izgladnjivanja" procesa, dugo čekanje da udje u
  kritičnu sekciju, jer drugi procesi imaju više "sreće", ali u praksi se retko
  dogadja.

## Monitori
- najviši nivo apstrakcije po pitanju zaštite kritične sekcije
- konstrukcije programskih jezika, za razliku od brojačkih semafora koji se
  implementiraju na nivout operativnog sistema, koje sadrže sopstvene
  promenljive i funkcije.
- u jednom trenutku, samo jedan proces može da bude unutar monitora i da
  pristupi njegovim funkcijama, dok ostali procesi moraju da čekaju da on
  završi sa radom.
- za sinhronizaciju se koriste posebne uslovne promenljive i operacije nad
  njima, **wait** i **signal**.
- proces se može blokirati sa **x.wait()** i kasnije odblokirati sa
  **x.signal()**.
- razlika izmedju uslovnih promenljivih monitora i brojačkih semafora je što
  kod brojačkih semafora čekanje procesa mora uslediti pre slanja signala za
  odblokiranje.
- ako neki proces čeka blokiran na signal, poslati sigal može da probudi samo
  taj proces, dok ostali čekaju naredne signale.
- ako nijedan proces ne čeka, poslati signal će biti izgubljen.

Realizacija monitora pomoću semfora

	mutex = 1; // semafor za eks. pristup monitoru
	brojac_procesa = 0;
	procesi = 1; // semafor za procese koji su trenutno u monitoru

	P(mutex); // testira se da li je mutex otkljucan
	P_i(...); // ako jeste, izvrsava se f-ja P_i
	// ako je mutex zakljucan, blokira se dok se ne otkljuca

	if (brojac_procesa > 0) // da li ima procesa u monitoru
		V(procesi); // propustiti sledeci proces na semaforu
	else
		V(mutex); // ako nema procesa koji cekaju za monitor
		          // oslobadja se prilaz monitoru

Implementacija operacija monitora

	x: struktura
		sem: semafor // semafor na kom ce procesi cekati
		brojac: ceo broj; // br. procesa koji cekaju

	wait()
		x.brojac++; // povecava se broj procesa koji cekaju
		if (brojac_procesa > 0) // ako postoje procesi koji su vec blokirani
                                // na semaforu procesi

			V(procesi); // propusta se jedan blokirani proces
		else
			V(mutex);
			// ako nema blok. procesa, oslabadja se pristup monitoru

		P(x.sem); // proces se blokira na semaforu
		x.brojac--; // kada se proces odblokira, smanjuje se br. procesa koji
		               cekaju

	signal()
		if (x.brojac > 0) // ako postoje procesi koji cekaju na semaforu
                             u suprotnom nema potrebe slati signal
		brojac_procesa++;
		V(x.sem); // propusta se jedan proces sa semafora

		P(procesi); // blokiraju se procesi tren. u monitoru
                       jer je upravo odblokiran jedan proces
		brojac_procesa--;

## Razlika izmedju multiprogramiranja i multitaskinga
- multitasking je moderniji (efikasniji) pristup u odnosu na multiprogramiranje
- dok se multiprogramiranje zasniva na konceptu učitavanja više programa u
  radnu memoriju i njihovog konkurentnog izvršavanja i smenjivanja na
  procesoru kad nekom procesu ne dodju ulazno-izlazne operacije, multitasking
  podrazumeva da je jedinica izvršavanja na procesoru posao (task), koji ne
  mora nužno da se izvršava izmedju dve ulazno-izlazne operacije.
- kao i kod multiprogramiranja, i kod multitaskinga se po izvršavanju posla
  oslobadja procesor za naredni posao.
- ova dva pojma se često poistovećuju jer su dosta slični.

## Asocijativna memorija i njene primene
- koristi se za veoma brzu i efikasnu implementaciju tabele stranica kod
  sistema sa strničenjem.
- asocijativna memorija ili TLD (Translation Lookaside Buffer) je keš memorija
  koja je posebno dizajnirana za straničenje tako što čuva deo tabele stranica.
- čuva memoriju u parovima ključeva i vrednosti, a pretraga nad njima se vrši
  simultano.
- ključevi su redni brojevi stranica, a njihove vrednosti su adrese memorijskih
  okvira.
- kad procesor pokuša da pristupi nekom delu logičke memorije, najpre traži u
  asocijativnoj memoriji i ako je nadje (pogodak), odmah može da pročita adresu okvira.
  Ako je ne nadje tako (promašaj), pretražuje deo tabele stranica koji je u memoriji.
- procent uspešnog pronalaska stranice u asocijativnoj memoriji je nivo
  pogodaka (hit ratio)
