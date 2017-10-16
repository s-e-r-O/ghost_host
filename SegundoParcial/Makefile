CC = gcc
IDIR = ./include
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = lpcap 
LIBS = lnet
OBJ = main.c ./source/*.c
DEPS = $(IDIR)/*

parcial2: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -$(LIBS) -lpcap

# clean out the dross
clean:
	rm -f parcial2  *~ *.o
