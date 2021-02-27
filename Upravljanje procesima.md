# Upravljanje procesima

## 1. Procesi
Program u izvršavanju
### Proces u memoriji
- procesi u memoriji raspolazu sa:
	- **stek segmentom** - lokalne promenljive i param. funkcija
	- **hip segment** - podaci koji se gen. tokom rada programa
	- **segment podataka** - globalne promeljive
	- **kod segment** - instrukcije za izvrsavanje
## 2. Stanja procesa
- **Novi** - upravo kreiran, prelazi u spremno stanje
- **Spreman** - procesor čeka da mu se dodeli rad na procesoru
- **Izvršavanje** - izvršava se na procesoru
- **Čeakanje** - OS je zaustavio proces i čeka da se nastavi sa
  izvršavanjem
- **Završen** - završio sa radom i izbacuje se iz sistema

Promene stanja mogu biti:
- **iz Spreman u Izvršavanje** - procesor se oslobodi i OS odluči
  da procesu dodeli procesor.
- **iz Izvršavanja u Čekanje** - za dalje izvršavanje procesa su
  potrebi resursi koji su trenutno nedostupni, pa proces čeka.
- **iz Izvršavanja u Spreman** - isteklo je unapred odredjeno vreme
  za rad procesa ili je OS odlučio procesor da da nekom drugom
  procesu.
- **iz Čekanja u Spreman** - oslobodili su se potrebi resursi i
  može da nastavi sa radom.

Procesi se mogu **[suspendovati](suspendovati.md)**, pa ako su bili _spremni_ ili _čekali_,
prelaze u **suspendovan i spreman** ili **suspendovan i čeka**.
## 3. Kontrolni blok procesa

Sadrži najznačajnije podatke za indetifikaciju i upravljanje procesima.

U vecini implementacija sadrži:
- **Jedinstveni identifikator (PID)**
- **Stanje procesa**
- **Programski brojač** - pamti sledecu instrukciju koju proces treba da
izvrši (ako dodje do prekida procesa)
- **Sadržaj registara procesora** - ako dodje do prekida, da može da
nastavi sa radom
- **Prioritet procesa**
- **Adresa procesa u memoriji**
- **Adrese zauzetih resursa**

**Prebacivanje konteksta** je postupak kojim se trenutni proces prekida,
pamte njegovi podaci i pokrece drugi proces.
Za prebacivanje konteksta u OS-u je zadužen **dispečer**.
## 4. Niti

Predstavljaju delove nekog procesa i koriste resurse tog procesa.
Niti sa procesom dele kod segment, segment podataka, hip segment, a imaju
zasebni stek, registre, programski brojač.

Zbog deljenja memorije sa procesorom, korišcenje niti pomaze da se znatno
uštedi na prostoru i takodje u brzini, jer se brze kreiraju od celih procesa.

Niti se dele na korisničke i niti jezgra, na osnovu toga da li se njima
upravlja na korisničkom ili sistemskom nivou.

Pošto pristup procesoru i priliku da se izvršavaju jedino imaju niti
jezgra, postoji nekoliko vrsti preslikvanja sistemskih u korisničke niti:

- **više korsničkih u jednu sistemsku**
	* pošto **jezgro radi isklučivo sa procesima**, svaka nit
	predstavlja jedan proces.
	* nedostatak ovog pristupa je, ako dodje do blokiranja neke
	korisničke niti, blokira se i odgovarajuca nit jezgra, tj. celog
	procesa
- **jedna u jednu**
	* upravljanje nitima se potpuno prepušta jezgru
	* sporije se prave i manje ih je, ali jezgro ima bolju podršku za
	rad nad njima
	* rešava se prethodni nedostatak, dozvoljava konkurentnije
	izvršavanje niti
	* mana je vreme i resursi potrebni za stvaranje niti jezgra
- **više u više**
	* hibrid prethodna dva, kor. niti se preslikavaju u manji ili isti
	broj niti jezgra.
	* broj niti, kao i rasporedjivanje kor. na niti jezgra, je na kor.
	nivou, dok je upravljanje na sistemskom

## Redovi procesa
