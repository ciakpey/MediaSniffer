Summary: Sniff download links of online media.
Name: mediasniffer
Version: 1.0.0.12
Release: 1%{?dist}
Group: Applications/Internet
License: GPL
Source: mediasniffer-linux-src-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
URL: http://sourceforge.net/projects/mediasniffer/
BuildArch: i686
Requires: libcurl libpcap

%description
Sniff download links of media when you watching online videos, listening to online musics or downloading from iTunes.

%prep
%setup -c
%build
make prefix=%{_prefix}
%install
make prefix=%{_prefix} DESTDIR=$RPM_BUILD_ROOT install

%files
%{_sysconfdir}/pam.d/mediasniffer
%{_sysconfdir}/security/console.apps/mediasniffer
%{_sbindir}/mediasniffer
%{_bindir}/mediasniffer
%{_datadir}/applications/mediasniffer.desktop
%{_datadir}/pixmaps/mediasniffer.png
%{_datadir}/pixmaps/mediasniffer/icon.png
%{_datadir}/doc/mediasniffer/ChangeLog
%{_datadir}/doc/mediasniffer/LICENSE
%{_datadir}/doc/mediasniffer/README

%clean
make clean

