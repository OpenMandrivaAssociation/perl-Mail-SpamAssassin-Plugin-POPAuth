Summary:	The POPAuth plugin for SpamAssassin
Name:		perl-Mail-SpamAssassin-Plugin-POPAuth
Version:	0
Release:	%mkrel 2
License:	Apache License
Group:		Development/Perl
URL:		http://people.apache.org/~dos/sa-plugins/3.1/
Source0:	http://people.apache.org/~dos/sa-plugins/3.1/POPAuth.cf.bz2
Source1:	http://people.apache.org/~dos/sa-plugins/3.1/POPAuth.pm.bz2
Patch0:		POPAuth-fix-module-path.patch
Requires(pre): rpm-helper
Requires(postun): rpm-helper
Requires(pre):  spamassassin-spamd >= 3.1.1
Requires:	spamassassin-spamd >= 3.1.1
BuildRequires:	perl-doc
BuildArch:	noarch
Buildroot:	%{_tmppath}/%{name}-%{version}-root

%description
Utilizes an access.db style hash file to extend the SpamAssassin
trusted_networks to 'POPAuth' or 'POP-before-SMTP' hosts by dynamically adding
and removing the hosts or networks found in the specified database to
SpamAssassin's trusted_networks configuration. 

%prep

%setup -q -T -c -n %{name}-%{version}

bzcat %{SOURCE0} > POPAuth.cf
bzcat %{SOURCE1} > POPAuth.pm

%patch0

%build

perldoc POPAuth.pm > Mail::SpamAssassin::Plugin::POPAuth.3pm

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

install -d %{buildroot}%{_sysconfdir}/mail/spamassassin/
install -d %{buildroot}%{perl_vendorlib}/Mail/SpamAssassin/Plugin
install -d %{buildroot}%{_mandir}/man3

install -m0644 POPAuth.cf %{buildroot}%{_sysconfdir}/mail/spamassassin/
install -m0644 POPAuth.pm %{buildroot}%{perl_vendorlib}/Mail/SpamAssassin/Plugin/
install -m0644 Mail::SpamAssassin::Plugin::POPAuth.3pm %{buildroot}%{_mandir}/man3/

%post
if [ -f %{_var}/lock/subsys/spamd ]; then
    %{_initrddir}/spamd restart 1>&2;
fi
    
%postun
if [ "$1" = "0" ]; then
    if [ -f %{_var}/lock/subsys/spamd ]; then
        %{_initrddir}/spamd restart 1>&2
    fi
fi

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(644,root,root,755)
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/mail/spamassassin/POPAuth.cf
%{perl_vendorlib}/Mail/SpamAssassin/Plugin/POPAuth.pm
%{_mandir}/man3/Mail::SpamAssassin::Plugin::POPAuth.3pm*

