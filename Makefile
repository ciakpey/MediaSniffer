VERSION = 1.0.0.13

prefix ?= /usr
bindir ?= $(prefix)/bin
sbindir ?= $(prefix)/sbin
datadir ?= $(prefix)/share
sysconfdir ?= /etc

PAMD = $(sysconfdir)/pam.d
CONSAPP = $(sysconfdir)/security/console.apps
CONHELP = /usr/bin/consolehelper
TPAMD = pam.d
TCONS = consapp

APP = mediasniffer
DOCDIR = $(datadir)/doc/$(APP)
INIFILE = /etc/$(APP).ini

CPPC = g++
CPPARGS = -pipe -Wall `pkg-config --cflags --libs gtk+-2.0 gdk-2.0 gthread-2.0 libgnome-2.0 libgnomeui-2.0` -lpcap -lcurl -O2 -Xlinker -s

HDR = MediaSniffer/config.h MediaSniffer/platform.h MediaSniffer/Hash.h MediaSniffer/MediaSniffer.h linux_gui/configdlg.h linux_gui/update.h linux_gui/uicommon.h

SRC = MediaSniffer/config.cpp MediaSniffer/platform.cpp MediaSniffer/Hash.cpp MediaSniffer/MediaSniffer.cpp linux_gui/configdlg.cpp linux_gui/update.cpp linux_gui/entry.cpp

all: $(HDR) $(SRC)
	echo "#define APP \"$(APP)\"" > config.h;\
	echo "#define PREFIX \"$(prefix)\"" >> config.h;\
	echo "const char kVersion[] = \"$(VERSION)\";" >> config.h;\
	$(CPPC) $(CPPARGS) $(SRC) -o $(APP)

install:
	echo "#%PAM-1.0" > $(TPAMD);\
	echo "auth		include		config-util" >> $(TPAMD);\
	echo "account		include		config-util" >> $(TPAMD);\
	echo "session		include		config-util" >> $(TPAMD);\
	echo "USER=root" > $(TCONS);\
	echo "PROGRAM=$(prefix)/sbin/$(APP)" >> $(TCONS);\
	echo "SESSION=true" >> $(TCONS);\
	mkdir -p $(DESTDIR)$(sbindir);\
	cp $(APP) $(DESTDIR)$(sbindir);\
	mkdir -p $(DESTDIR)$(datadir)/pixmaps/$(APP);\
	cp linux_gui/icon.png $(DESTDIR)$(datadir)/pixmaps/$(APP);\
	ln -s $(datadir)/pixmaps/$(APP)/icon.png $(DESTDIR)$(datadir)/pixmaps/$(APP).png;\
	mkdir -p $(DESTDIR)$(datadir)/applications;\
	cp linux_gui/$(APP).desktop $(DESTDIR)$(datadir)/applications/;\
	mkdir -p $(DESTDIR)$(DOCDIR);\
	cp ChangeLog.txt $(DESTDIR)$(DOCDIR)/ChangeLog;\
	cp License.txt $(DESTDIR)$(DOCDIR)/LICENSE;\
	cp ReadMe.txt $(DESTDIR)$(DOCDIR)/README;\
	mkdir -p $(DESTDIR)$(bindir);\
	ln -s $(CONHELP) $(DESTDIR)$(bindir)/$(APP);\
	mkdir -p $(DESTDIR)$(PAMD);\
	cp $(TPAMD) $(DESTDIR)$(PAMD)/$(APP);\
	mkdir -p $(DESTDIR)$(CONSAPP);\
	cp $(TCONS) $(DESTDIR)$(CONSAPP)/$(APP);\

mininstall:
	cp $(APP) $(sbindir)

clean:
	rm $(APP) config.h $(TPAMD) $(TCONS)

uninstall:
	rm $(sbindir)/$(APP);\
	rm -r $(datadir)/pixmaps/$(APP);\
	rm -r $(DOCDIR);\
	rm $(datadir)/pixmaps/$(APP).png;\
	rm $(datadir)/applications/$(APP).desktop;\
	rm $(bindir)/$(APP);\
	rm $(PAMD)/$(APP);\
	rm $(CONSAPP)/$(APP)

dist:
	tar -jcvf $(APP)-linux-src-$(VERSION).tar.bz2 $(HDR) $(SRC) Makefile ChangeLog.txt ReadMe.txt License.txt linux_gui/icon.png linux_gui/mediasniffer.desktop mediasniffer.spec

