psxtract
========

Tool to decrypt and convert PSOne Classics from PSP/PS3.
Written by **Hykem**.

This tool allows you to decrypt a PSOne Classics EBOOT.PBP on your PC, using
the emulated PSP method.
It features a modified version of libkirk's source code to support DES
encryption/decryption and the AMCTRL functions.


Notes
-------

You may supply a KEYS.BIN file to the tool, but this is not necessary.
Using the internal files' hashes, psxtract can calculate the key by itself.

Game file manual decryption is also supported (DOCUMENT.DAT).

For more details about the algorithms involved in the extraction process
please check the following sources:
- PBP unpacking: 
  https://github.com/pspdev/pspsdk/blob/master/tools/unpack-pbp.c

- PGD decryption:
  http://www.emunewz.net/forum/showthread.php?tid=3834 (initial research)
  https://code.google.com/p/jpcsp/source/browse/trunk/src/jpcsp/crypto/PGD.java (JPCSP)
  https://github.com/tpunix/kirk_engine/blob/master/npdrm/dnas.c (tpunix)

- AMCTRL functions:
  https://code.google.com/p/jpcsp/source/browse/trunk/src/jpcsp/crypto/AMCTRL.java (JPCSP)
  https://github.com/tpunix/kirk_engine/blob/master/kirk/amctrl.c (tpunix)


Credits
-------

Draan, Proxima and everyone involved in kirk-engine (libkirk source code)

tpunix (C port and research of the PGD and AMCTRL algorithms)

PSPSDK (PBP unpacking sample code)
