CC = gcc
IDIR = .
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = -lnet -lpcap
OBJ = main.c
DEPS = $(IDIR)/*

lnet_test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

# clean out the dross
clean:
	rm -f lnet_test  *~ *.o
