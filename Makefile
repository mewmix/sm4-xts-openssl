all: sm4_xts xts_debug

sm4_xts:
	@echo "Building sm4_xts"
	gcc -o sm4_xts sm4_xts.c -lssl -lcrypto
	gcc -o sm4_xts sm4_xts.c -I/opt/homebrew/opt/openssl@3/include 
-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

xts_debug:
	@echo "Building xts_debug"
	gcc -o xts_debug xts_debug.c -lssl -lcrypto

	gcc -o xts_debug xts_debug.c -I/opt/homebrew/opt/openssl@3/include 
-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
