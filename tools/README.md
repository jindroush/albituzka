
### Prostředí
Všechny nástroje byly napsány pod Windows 10, na ActiveState Perlu 5.24.3. Pro běh na jiném OS by neměly být teoreticky
potřebné žádné úpravy. Je možné, že bude nutno doinstalovávat některé moduly, které nejsou typickou součástí instalace,
např. Imager, Imager::Fill, MP3::Info a další. Jakým způsobem doinstalovat moduly lze dohledat v dokumentaci.
Všechny nástroje jsou pouze příkazovo-řádkové, nemají žádné grafické rozhraní.

### Popis nástrojů v tomto adresáři

creator/bnl_creator.pl - generuje BNL soubor ze mnoha mp3 souborů a bnl.json. Tyto lze získat pomocí bnl_dis.pl z existujícího bnl souboru

disassembler/bnl_dis.pl - rozebírá BNL soubor na mp3 soubory a bnl.json.

firmware_cutter/fw_cutter.pl - identifikuje a rozřezává obsah firmware souboru update.chp

oid_generator/oid_png_generator - generuje vytisknutelný png soubor s jedním OID kódem.

oid_rawtable/oid_table_extract - extrahuje konverzní tabulku OID 2.0 raw kódů na interní kódy z nástroje OidCreator
