=head1 NAME

Mail::SpamAssassin::Plugin::POPAuth

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::POPAuth [/path/to/POPAuth.pm]

 popauth_hash_file /path/to/access.db

=head1 DESCRIPTION

Utilizes an access.db style hash file to extend the SpamAssassin
trusted_networks to 'POPAuth' or 'POP-before-SMTP' hosts by
dynamically adding and removing the hosts or networks found in the
specified database to SpamAssassin's trusted_networks configuration.

LHS hosts or networks in the database may be specified in either classful
or classless notations.

Each entry found in the database with a RHS of I<OK> or I<RELAY> is
added to the trusted_networks.  Any other entry is ignored.  Only the first
entry for a host or network is used.  Subsequent entries are ignored.

Note: only the first word (split on non-word characters) of the RHS is
checked.

B<AccessDB Pointers:>

  http://www.faqs.org/docs/securing/chap22sec178.html
  http://www.postfix.org/access.5.html

=head1 AUTHOR

Daryl C. W. O'Shea, DOS Technologies <spamassassin@dostech.ca>

=head1 COPYRIGHT

Copyright (c) 2005 Daryl C. W. O'Shea, DOS Technologies. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=cut

package Mail::SpamAssassin::Plugin::POPAuth;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Fcntl;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DB_FILE => eval { require DB_File; };


sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # Ignore the first message except when using 'spamassassin' to avoid copy_config issues.
  $self->{linted} = ($0 =~ /\/spamassassin$/ ? 1 : 0);

  $self->{failed} = 0;

  $self->set_config($mailsaobject->{conf});

  return $self;
}


sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=item popauth_hash_file /path/to/access.db	default: /etc/mail/access.db

Path to your POPAuth hash database.

B<Note:> This file MUST be readable by any user that a SpamAssassin child may
potentially run as (any user specified in a -u parameter that would be getting
mail from a POPAuth host). In most cases the file will need to be globally
readable.

=cut

  push (@cmds, {
    setting => 'popauth_hash_file',
    is_admin => 1,
    default => "/etc/mail/access.db",
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if (-d $value) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{popauth_hash_file} = $value;
      dbg("config: setting POPAuth hash file: $value");
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}


sub check_start {
  my ($self, $opts) = @_;

  return unless (HAS_DB_FILE);

  # prevent M::SA->copy_config from copying dynamically added trusted_networks
  unless ($self->{linted}) {
    $self->{linted} = 1;
    return;
  }

  dbg_trusted($self, 0);

  my ($num_trusted, %trusted) = $self->_read_hash_db($self);

  unless (defined $num_trusted) {
    $opts->{permsgstatus}->{main}->{conf}->{headers_spam}->{POPAuth} = "Database Failure";
    $opts->{permsgstatus}->{main}->{conf}->{headers_ham}->{POPAuth} = "Database Failure";
    return;
  }

  dbg("config: $num_trusted useful lines found in POPAuth database");

  my $added = 0;
  while (my($quad, $bits) = each(%trusted)) {
    if ($self->{main}->{conf}->{trusted_networks}->contains_ip($quad)) {
      dbg("config: ip: $quad already exists in trusted_networks");
    } else {
      dbg("config: ip: $quad not in trusted_networks");

      if ($self->{main}->{conf}->{trusted_networks}->add_cidr("$quad/$bits")) {
	dbg("config: added $quad/$bits to trusted_networks");
	$added++;
      } else {
	dbg("config: failed to add $quad/$bits to trusted_networks");
      }

      my $aton = Mail::SpamAssassin::Util::my_inet_aton($quad);
      my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);

      $self->{added_aton}->{$aton} = $mask;
    }
  }

  dbg("config: added $added POPAuth entries to trusted_networks");
  dbg_trusted($self, 0);

  return;
}


sub parsed_metadata {
  my ($self, $opts) = @_;

  return unless (HAS_DB_FILE && $self->{linted} && !$self->{failed});

  # We have to check every relay as the last one might not be the one that
  # caused all of them to be trusted.  Be aware of netmasks.
  foreach my $relay (@{$opts->{permsgstatus}->{relays_trusted}}) {
    my $relay_aton = Mail::SpamAssassin::Util::my_inet_aton($relay->{ip});
    while (my($aton, $mask) = each (%{$self->{added_aton}})) {
      if (($relay_aton & $mask) == $aton) {
	$opts->{permsgstatus}->{main}->{conf}->{headers_ham}->{POPAuth} = 'Yes';
	$opts->{permsgstatus}->{main}->{conf}->{headers_spam}->{POPAuth} = 'Yes';
	return;
      }
    }
  }

  $opts->{permsgstatus}->{main}->{conf}->{headers_ham}->{POPAuth} = 'No';
  $opts->{permsgstatus}->{main}->{conf}->{headers_spam}->{POPAuth} = 'No';
  return;
}


sub _read_hash_db {
  my ($self) = @_;

  my %access;
  my %trusted;
  my %ok = map { $_ => 1 } qw/ OK RELAY /;

  my $path = $self->{main}->{conf}->{popauth_hash_file};

  $path = $self->{main}->sed_path ($path);
  dbg("config: tie-ing to DB file R/O in $path");

  if (tie %access,"DB_File",$path, O_RDONLY) {
    my %cache = ();
    while(my($key, $value) = each(%access)) {
      # We only care about the first entry for any given host/network.
      next if ($cache{$key}++);

      # Some systems put a null at the end of the key, most don't.
      $key =~ s/\000//;

      # We only care about the first word of the RHS value.
      my ($type) = split(/\W/,$value);
      $type = uc $type;

      if (exists $ok{$type}) {
	# If it's in CIDR notation get the number of bits.
	my $bits;
	if ($key =~ s/^\s*([\d.]+)\/(\d{1,2})\s*$/$1/) { $bits = $2; }

	# We'll probably only ever get /32 addresses, but what the heck.
	if    ($key =~ /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$/) { $trusted{"$1.$2.$3.$4"} = ($bits || 32); }
	elsif ($key =~ /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.?\s*$/)	     { $trusted{"$1.$2.$3.0"} = ($bits || 24); }
	elsif ($key =~ /^\s*(\d{1,3})\.(\d{1,3})\.?\s*$/)		     { $trusted{"$1.$2.0.0"} = ($bits || 16); }
	elsif ($key =~ /^\s*(\d{1,3})\.?\s*$/)		   		     { $trusted{"$1.0.0.0"} = ($bits || 8); }
	else  { dbg("config: could not parse POPAuth database pair: '$key' => '$value', skipping"); }
      }
    }

    dbg("config: untie-ing DB file $path");
    untie %access;

  } else {
    dbg("config: failed to tie DB");
    $self->{failed} = 1;
    return (undef, %trusted);
  }

  my $size = keys %trusted;
  return ($size, %trusted);
}


sub dbg_trusted {
  my ($self, $verbose) = @_;

  dbg("config: current number of trusted_networks: " . $self->{main}->{conf}->{trusted_networks}->get_num_nets);
  if ($verbose) {
    foreach my $net (@{$self->{main}->{conf}->{trusted_networks}->{nets}}) {
      dbg("config: trusted ip: $net->{ip} mask: $net->{mask}");
    }
  }
}


1;
