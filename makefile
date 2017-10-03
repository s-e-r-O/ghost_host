CC = gcc
IDIR = ./include
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = -lnet -lpcap
OBJ = main.c ./source/*.c
DEPS = $(IDIR)/*

ghost_host: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

# clean out the dross
clean:
	rm -f ghost_host  *~ *.o
