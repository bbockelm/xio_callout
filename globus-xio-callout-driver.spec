Name:		globus-xio-callout-driver
Version:	0.1
Release:	1%{?dist}
Summary:	An XIO driver that simply periodically calls a script.

Group:		Development/Libraries
License:	ASL 2.0
URL:		https://github.com/bbockelm/xio_callout
# Generated from:
# git archive --format=tgz --prefix=%{name}-%{version}/ v%{version} > %{name}-%{version}.tar.gz
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	globus-xio-devel
BuildRequires:  cmake

%description
%{summary}

%prep
%setup -q


%build
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_LIBDIR=%{_libdir} .
make VERBOSE=1 %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}


%files
%doc
%{_libdir}/libglobus_xio_callout_driver.so*

%changelog
* Tue Jul 12 2016 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1-1
- Initial packaging of callout driver.


