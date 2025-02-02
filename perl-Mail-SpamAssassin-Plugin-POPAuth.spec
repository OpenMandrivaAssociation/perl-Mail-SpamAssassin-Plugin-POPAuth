Summary:	The POPAuth plugin for SpamAssassin
Name:		perl-Mail-SpamAssassin-Plugin-POPAuth
Version:	0
Release:	9
License:	Apache License
Group:		Development/Perl
URL:		https://people.apache.org/~dos/sa-plugins/3.1/
Source0:	http://people.apache.org/~dos/sa-plugins/3.1/POPAuth.cf
Source1:	http://people.apache.org/~dos/sa-plugins/3.1/POPAuth.pm
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

cp %{SOURCE0} POPAuth.cf
cp %{SOURCE1} POPAuth.pm

# fix path
perl -pi -e "s|/etc/mail/spamassassin/POPAuth\.pm|%{perl_vendorlib}/Mail/SpamAssassin/Plugin/POPAuth\.pm|g" POPAuth.cf

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


%changelog
* Fri Sep 04 2009 Thierry Vignaud <tv@mandriva.org> 0-7mdv2010.0
+ Revision: 430490
- rebuild

* Thu Jul 31 2008 Thierry Vignaud <tv@mandriva.org> 0-6mdv2009.0
+ Revision: 257719
- rebuild

* Thu Jul 24 2008 Thierry Vignaud <tv@mandriva.org> 0-5mdv2009.0
+ Revision: 245817
- rebuild

* Wed Jan 02 2008 Olivier Blin <oblin@mandriva.com> 0-3mdv2008.1
+ Revision: 140691
- restore BuildRoot

  + Thierry Vignaud <tv@mandriva.org>
    - kill re-definition of %%buildroot on Pixel's request

* Sun Jul 01 2007 Oden Eriksson <oeriksson@mandriva.com> 0-3mdv2008.0
+ Revision: 46363
- misc fixes


* Sat Nov 25 2006 Emmanuel Andry <eandry@mandriva.org> 0-2mdv2007.0
+ Revision: 87287
- patch to fix perl module path
- Import perl-Mail-SpamAssassin-Plugin-POPAuth

