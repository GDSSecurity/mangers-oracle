LD_FLAGS = -lgcrypt -L ../libs/lib -Wl,-rpath,../libs/lib
CC_FLAGS = -Wall --pedantic-errors -g

all : 
	g++ $(LD_FLAGS) $(CC_FLAGS) encryptoracle.c -o encrypt
	g++ $(LD_FLAGS) $(CC_FLAGS) decryptoracle.c -o decrypt
debug :
	g++ $(LD_FLAGS) $(CC_FLAGS) -DEBUG encryptoracle.c -o encrypt
	g++ $(LD_FLAGS) $(CC_FLAGS) -DEBUG decryptoracle.c -o decrypt
clean : 
	rm -rf encrypt decrypt *~