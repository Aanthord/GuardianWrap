Name: guardian-wrapper
Version: 1.0
Release: 1
Summary: A guardian wrapper for Linux applications with enhanced security features
License: GPL
Source: %{name}-%{version}.tar.gz
BuildRequires: gcc, make, liboqs-devel, openssl-devel
Requires: liboqs, openssl

%description
Guardian wrapper enhances Linux application security with stack canary monitoring,
secure and immutable logging using BLAKE3, and real-time monitoring capabilities.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/local/bin/guardian-wrapper

%pre
# Commands to run before installation, e.g., checking for dependencies

%post
# Commands to run after installation, e.g., setting up environment variables

%preun
# Commands to run before uninstallation

%postun
# Commands to run after uninstallation

%changelog
* Date Author - Version-Release
- Initial RPM release

