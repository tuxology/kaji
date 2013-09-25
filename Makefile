include Makefile.inc

DIRS = demo src

all: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

.PHONY: clean $(DIRS)
clean:
	-for d in $(DIRS); do (cd $$d; $(MAKE) clean); done;
