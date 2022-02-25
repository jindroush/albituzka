# albituzka
Reverzní inženýrství Albi Kouzelného čtení.

V adresáři docs je popis formátu BNL a obsahu firmware.

V adresáři tools pak nástroje k rozebrání a složení BNL souboru, generátor OID kódů a další nástroje.


English:
Reverse engineering of BNL files used for Albi electronic pen. Works also for files found on SpeakItBooks.com. To check if this description is valid for your BNL files, XOR first two 32bit DWORDs, you should get 0x200 in little endian.
