;uses assembly.py from s9ke github, with slighly added functionality (.word keyword, possibility to use labels in imm assignments)
;several functions called are in 0x42xxxx address space, ie. firmware. To make this work, you'd need to find the same
;functions in your firmware.

;free space in the original firmware
seek(0x42a080)

;just a prologue, 0x100 in locals, not sure which DMs saved
Y0.h = 0x01
Y0.l = 0x00
X1.h = 0x30
X1.l = 0x0f
;prologue
Callff 0x000b42

;file mode for writing wb+ (write, binary, also read)
R0.h = .label_mode.lh
R0.l = .label_mode.ll
push R0
R0.h = .label_mode.hh
R0.l = .label_mode.hl
push R0

;filename on sdcard
R0.h = .label_fname.lh
R0.l = .label_fname.ll
push R0
R0.h = .label_fname.hh
R0.l = .label_fname.hl
push R0

;File_Open_Lib_Call_Probably_stack(szFname,szAccess)_ret_handle_in_R0
Callff 0x4218e4
;naked_pop_4_words
Callff 0x000c51
DM(0x00b) = R0
X1 = R0 OR R0
Jeq .go_error ;when failed

R0 = 0x00
;IO(Ix0Bk) = R0
.word 0xe28e
R0 = 0x00
;IO(Ix0)=R0
.word 0xe282

;blocks counter
R0 = 0x00
DM(0x00d) = R0

.loop_sectors:
;word counter
R0 = 0x00
DM(0x00c) = R0

.loop_block:
R0 = ROM(Ix0, 1)
Y1 = DM(0x00c)
;save one rom word to local var DM(0x00c)
;naked_local(Y1)=R0
Callff 0x000bc5

;increment counter
R0 = DM(0x00c)
R1 = R0 + 1
DM(0x00c) = R1
Y1.l = 0x00
Y1.h = 0x01
R0 = R1 - Y1
;loop unless we copy 0x100 words
jnac .loop_block

;push io[ix0]
.word 0xfc82

;save one sector 0x200 bytes from locals to file
X0 = DM(0x00b)
Push X0
R0 = DM(0x000)
Push R0
Callff 0x28aa9c
Pop X0
Pop X0
;here should be test, but we'll just ignore it

;pop io[ix0]
.word 0xfcc2

;increment block counter
R0 = DM(0x00d)
R1 = R0 + 1
DM(0x00d) = R1

;is it the end of 'low' rom?
Y1.l = 0x40
Y1.h = 0x00
R0 = R1 - Y1
jne .loop_check

;if so, switch to 'high' rom
R0 = 0x28
;IO(Ix0Bk) = R0
.word 0xe28e
R0 = 0x00
;IO(Ix0)=R0
.word 0xe282

.loop_check:
Y1.l = 0x00
Y1.h = 0x01
R0 = R1 - Y1
jnac .loop_sectors

;everything saved, close  file
X0 = DM(0x00b)
Push X0
;File_Close_Lib_Probably_stk(wHandle)
Callff 0x4277e9
Pop X0

;say blum! to know we're not stuck
X0 = 0xc2   ;sound 2/194, [jingle 7]
Push X0
;Play_sound_from_2bin_table_stk(wSoundNum)
Callff 0x422324
Pop X0

;done, bye!
.go_error:
Y1.h = 0x30
Y1.l = 0x0f
;FunctionEpilogue(X1)
Jmpff 0x000b9e


.label_mode:
.word "w"
.word "b"
.word "+"
.word 0x0

.label_fname:
.word "s"
.word "d"
.word ":"
.word "0"
.word ":"
.word "\"
.word "s"
.word "n"
.word "9"
.word "5"
.word "3"
.word "0"
.word "2"
.word "."
.word "r"
.word "o"
.word "m"
.word 0x0

