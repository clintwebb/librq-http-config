## make file for librq-http-config.


PROJECT=librq-http-config
DESTDIR=
SONAME=$(PROJECT).so.1
LIBFILE=$(SONAME).0.1
OBJFILE=$(PROJECT).o

INCDIR=$(DESTDIR)/usr/include
LIBDIR=$(DESTDIR)/usr/lib

ARGS=-Wall -O2 -g


all: $(LIBFILE)



# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

$(OBJFILE): $(PROJECT).c rq-http-config.h
	gcc -c -fPIC $(PROJECT).c -o $@ $(ARGS)

$(PROJECT).a: $(OBJFILE)
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

$(LIBFILE): $(OBJFILE)
	gcc -shared -Wl,-soname,$(SONAME) -o $(LIBFILE) $(OBJFILE)
	

install: $(LIBFILE) rq-http-config.h
	@-test -e $(INCDIR)/rq-http-config.h && rm $(INCDIR)/rq-http-config.h
	cp rq-http-config.h $(INCDIR)/
	cp $(LIBFILE) $(LIBDIR)/
	@-test -e $(LIBDIR)/$(PROJECT).so && rm $(LIBDIR)/$(PROJECT).so
	ln -s $(LIBDIR)/$(LIBFILE) $(LIBDIR)/$(PROJECT).so


clean:
	@-[ -e $(OBJFILE) ] && rm $(OBJFILE)
	@-[ -e $(PROJECT).so* ] && rm $(PROJECT).so*
	@-rm *.o

