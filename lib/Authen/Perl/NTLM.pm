# -*- perl -*-
# NTLM.pm - An implementation of NTLM. In this version, I only
# implemented the client side functions that calculates the NTLM response.
# I will add the corresponding server side functions in the next version.
#

package Authen::Perl::NTLM;

use strict;
use Carp;
$Authen::Perl::NTLM::cChallenge = 0; # a counter to stir the seed that
                                     # generates the random number for the
                                     # nonce
$Authen::Perl::NTLM::PurePerl = undef; # a flag to see if we load pure perl 
                                       # DES and MD4 modules
eval "require Crypt::DES && require Digest::MD4";
if ($@) {
    eval "require Crypt::DES_PP && require Digest::Perl::MD4";
    if ($@) {
	die "Required DES and/or MD4 module doesn't exist!\n";
    }
    else {
        $Authen::Perl::NTLM::PurePerl = 1;
    }
}
else {
    $Authen::Perl::NTLM::PurePerl = 0;
}

if ($Authen::Perl::NTLM::PurePerl == 1) {
    require Crypt::DES_PP;
    Crypt::DES_PP->import;
    require Digest::Perl::MD4;
    import Digest::Perl::MD4 qw(md4);
}
else {
    require Crypt::DES;
    Crypt::DES->import;
    require Digest::MD4;
    import Digest::MD4;
}
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require DynaLoader;

*import = \&Exporter::import;

@ISA = qw (Exporter DynaLoader);
@EXPORT = qw ();
@EXPORT_OK = qw (nt_resp lm_resp negotiate_msg auth_msg compute_nonce);
$VERSION = '0.03';

# Stolen from Crypt::DES.
sub usage {
    my ($package, $filename, $line, $subr) = caller (1);
    $Carp::CarpLevel = 2;
    croak "Usage: $subr (@_)";
}

# These constants are stolen from samba-2.2.4 and other sources
use constant NTLMSSP_SIGNATURE => 'NTLMSSP';

# NTLMSSP Message Types
use constant NTLMSSP_NEGOTIATE => 1;
use constant NTLMSSP_CHALLENGE => 2;
use constant NTLMSSP_AUTH      => 3;
use constant NTLMSSP_UNKNOWN   => 4; 

# NTLMSSP Flags

# Text strings are in unicode
use constant NTLMSSP_NEGOTIATE_UNICODE                  => 0x00000001;
# Text strings are in OEM 
use constant NTLMSSP_NEGOTIATE_OEM                      => 0x00000002;
# Server should return its authentication realm 
use constant NTLMSSP_REQUEST_TARGET                     => 0x00000004;
# Request signature capability 
use constant NTLMSSP_NEGOTIATE_SIGN                     => 0x00000010; 
# Request confidentiality
use constant NTLMSSP_NEGOTIATE_SEAL                     => 0x00000020;
# Use datagram style authentication
use constant NTLMSSP_NEGOTIATE_DATAGRAM                 => 0x00000040;
# Use LM session key for sign/seal
use constant NTLMSSP_NEGOTIATE_LM_KEY                   => 0x00000080;
# NetWare authentication
use constant NTLMSSP_NEGOTIATE_NETWARE                  => 0x00000100;
# NTLM authentication
use constant NTLMSSP_NEGOTIATE_NTLM                     => 0x00000200;
# Domain Name supplied on negotiate
use constant NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      => 0x00001000;
# Workstation Name supplied on negotiate
use constant NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED => 0x00002000;
# Indicates client/server are same machine
use constant NTLMSSP_NEGOTIATE_LOCAL_CALL               => 0x00004000;
# Sign for all security levels
use constant NTLMSSP_NEGOTIATE_ALWAYS_SIGN              => 0x00008000;
# TargetName is a domain name
use constant NTLMSSP_TARGET_TYPE_DOMAIN                 => 0x00010000;
# TargetName is a server name
use constant NTLMSSP_TARGET_TYPE_SERVER                 => 0x00020000;
# TargetName is a share name
use constant NTLMSSP_TARGET_TYPE_SHARE                  => 0x00040000;
# TargetName is a share name
use constant NTLMSSP_NEGOTIATE_NTLM2                    => 0x00080000;
# get back session keys
use constant NTLMSSP_REQUEST_INIT_RESPONSE              => 0x00100000;
# get back session key, LUID
use constant NTLMSSP_REQUEST_ACCEPT_RESPONSE            => 0x00200000;
# request non-ntsession key
use constant NTLMSSP_REQUEST_NON_NT_SESSION_KEY         => 0x00400000;
use constant NTLMSSP_NEGOTIATE_TARGET_INFO              => 0x00800000;
use constant NTLMSSP_NEGOTIATE_128                      => 0x20000000;
use constant NTLMSSP_NEGOTIATE_KEY_EXCH                 => 0x40000000;
use constant NTLMSSP_NEGOTIATE_80000000                 => 0x80000000;

sub lm_resp($$);
sub nt_resp($$);
sub negotiate_msg($$$);
sub auth_msg($$$$$$$);
sub compute_nonce();
sub calc_resp($$);

#########################################################################
# lm_resp calculates the LM response for NTLM. It takes the nonce and 
# the user password to compute the 24-bytes LM response.
#########################################################################
sub lm_resp($$)
{
    my ($passwd, $nonce) = @_;
    my $cipher1;
    my $cipher2;
    my $magic = pack("H16", "4B47532140232425"); # magical string to be encrypted for the LM password hash
    while (length($passwd) < 14) {
	$passwd .= chr(0);
    }
    my $lm_pw = substr($passwd, 0, 14);
    $lm_pw = uc($lm_pw); # change the password to upper case
    my $key = convert_key(substr($lm_pw, 0, 7)) . convert_key(substr($lm_pw, 7, 7));
    if ($Authen::Perl::NTLM::PurePerl) {
	$cipher1 = Crypt::DES_PP->new(substr($key, 0, 8));
	$cipher2 = Crypt::DES_PP->new(substr($key, 8, 8));
    }
    else {
	$cipher1 = Crypt::DES->new(substr($key, 0, 8));
	$cipher2 = Crypt::DES->new(substr($key, 8, 8));
    }
    my $lm_hpw = $cipher1->encrypt($magic) . $cipher2->encrypt($magic) . pack("H10", "0000000000");
    return calc_resp($lm_hpw, $nonce);
} 

#########################################################################
# nt_resp calculates the NT response for NTLM. It takes the nonce and 
# the user password to compute the 24-bytes NT response.
#########################################################################
sub nt_resp($$)
{
    my ($passwd, $nonce) = @_;
    my $nt_pw = unicodify($passwd);
    my $nt_hpw;
    if ($Authen::Perl::NTLM::PurePerl == 1) {
	$nt_hpw = md4($nt_pw) . pack("H10", "0000000000");
    }
    else {
	my $md4 = new Digest::MD4;
        $md4->add($nt_pw);
	$nt_hpw = $md4->digest() . pack("H10", "0000000000");
    }
    return calc_resp($nt_hpw, $nonce);
}

####################################################################
# negotiate_msg creates the NTLM negotiate packet given the domain #
# (from Win32::DomainName()) and the workstation name (from        #
# $ENV{'COMPUTERNAME'} or Win32::NodeName()) and the negotiation   #
# flags.							   #
####################################################################
sub negotiate_msg($$$)
{
    my ($domain, $machine) = @_;
    my $flags = pack("V", $_[2]);
    my $msg = NTLMSSP_SIGNATURE . chr(0);
    $msg .= pack("V", NTLMSSP_NEGOTIATE);
    $msg .= $flags;
    my $offset = length($msg) + 8*2;
    $msg .= pack("v", length($domain)) . pack("v", length($domain)) . pack("V", $offset + length($machine)); 
    $msg .= pack("v", length($machine)) . pack("v", length($machine)) . pack("V", $offset);
    $msg .= $machine . $domain;
    return $msg;
}

###########################################################################
# auth_msg creates the NTLM response to an NTLM challenge from the        #
# server. It takes 7 arguments: lm_resp (from a call to lm_resp),         #
# nt_resp (from a call to nt_resp), user domain (from $ENV{'USERDOMAIN'}),#
# user name (from $ENV{'USERNAME'} or getlogin() or Win32::LoginName()),  #
# workstation name (from Win32::NodeName() or $ENV{'COMPUTERNAME'}),      #
# session key and negotiation flags.                                      #
# This function ASSUMEs the input of user domain, user name and           # 
# workstation name are in ASCII format and not in UNICODE format.         #
###########################################################################
sub auth_msg($$$$$$$)
{
    my ($lm_resp, $nt_resp, $domain, $username, $machine, $session_key) = @_;
    my $flags = pack("V", $_[6]);
    my $msg = NTLMSSP_SIGNATURE . chr(0);
    $msg .= pack("V", NTLMSSP_AUTH);
    my $offset = length($msg) + 8*6 + 4;
    $msg .= pack("v", length($lm_resp)) . pack("v", length($lm_resp)) . pack("V", $offset + 2*length($domain) + 2*length($username) + 2*length($machine) + length($session_key)); 
    $msg .= pack("v", length($nt_resp)) . pack("v", length($nt_resp)) . pack("V", $offset + 2*length($domain) + 2*length($username) + 2*length($machine) + length($session_key) + length($lm_resp)); 
    $msg .= pack("v", 2*length($domain)) . pack("v", 2*length($domain)) . pack("V", $offset); 
    $msg .= pack("v", 2*length($username)) . pack("v", 2*length($username)) . pack("V", $offset + 2*length($domain)); 
    $msg .= pack("v", 2*length($machine)) . pack("v", 2*length($machine)) . pack("V", $offset + 2*length($domain) + 2*length($username)); 
    $msg .= pack("v", length($session_key)) . pack("v", length($session_key)) . pack("V", $offset + 2*length($domain) + 2*length($username) + 2*length($machine)+ 48); 
    $msg .= $flags . unicodify($domain) . unicodify($username) . unicodify($machine) . $lm_resp . $nt_resp . $session_key;
    return $msg;
}

#######################################################################
# compute_nonce computes the 8-bytes nonce to be included in server's
# NTLM challenge packet.
#######################################################################
sub compute_nonce()
{
   my @SysTime = UNIXTimeToFILETIME(gmtime());
   my $Seed = (($SysTime[1] + 1) <<  0) |
              (($SysTime[2] + 0) <<  8) |
              (($SysTime[3] - 1) << 16) |
              (($SysTime[4] + 0) << 24);
   srand $Seed;
   $Authen::Perl::NTLM::cChallenge += 0x100;
   my $ulChallenge0 = (2**32)*rand; 
   my $ulChallenge1 = (2**32)*rand; 
   my $ulNegate = (2**32)*rand;
   if ($ulNegate & 0x1) {$ulChallenge0 |= 0x80000000;} 
   if ($ulNegate & 0x2) {$ulChallenge1 |= 0x80000000;} 
   return pack("V", $ulChallenge0) . pack("V", $ulChallenge1);
}

#########################################################################
# convert_key converts a 7-bytes key to an 8-bytes key based on an 
# algorithm.
#########################################################################
sub convert_key($) {
    my ($in_key) = @_; 
    my @byte;
    my $result = "";
    usage("exactly 7-bytes key") unless length($in_key) == 7;
    $byte[0] = substr($in_key, 0, 1);
    $byte[1] = chr(((ord(substr($in_key, 0, 1)) << 7) & 0xFF) | (ord(substr($in_key, 1, 1)) >> 1));
    $byte[2] = chr(((ord(substr($in_key, 1, 1)) << 6) & 0xFF) | (ord(substr($in_key, 2, 1)) >> 2));
    $byte[3] = chr(((ord(substr($in_key, 2, 1)) << 5) & 0xFF) | (ord(substr($in_key, 3, 1)) >> 3));
    $byte[4] = chr(((ord(substr($in_key, 3, 1)) << 4) & 0xFF) | (ord(substr($in_key, 4, 1)) >> 4));
    $byte[5] = chr(((ord(substr($in_key, 4, 1)) << 3) & 0xFF) | (ord(substr($in_key, 5, 1)) >> 5));
    $byte[6] = chr(((ord(substr($in_key, 5, 1)) << 2) & 0xFF) | (ord(substr($in_key, 6, 1)) >> 6));
    $byte[7] = chr((ord(substr($in_key, 6, 1)) << 1) & 0xFF);
    for (my $i = 0; $i < 8; ++$i) {
	$byte[$i] = set_odd_parity($byte[$i]);
	$result .= $byte[$i];
    }
    return $result;
}

##########################################################################
# set_odd_parity turns one-byte into odd parity. Odd parity means that 
# a number in binary has odd number of 1's.
##########################################################################
sub set_odd_parity($)
{
    my ($byte) = @_;
    my $parity = 0;
    my $ordbyte;
    usage("single byte input only") unless length($byte) == 1;
    $ordbyte = ord($byte);
    for (my $i = 0; $i < 8; ++$i) {
	if ($ordbyte & 0x01) {++$parity;}
	$ordbyte >>= 1;
    }
    $ordbyte = ord($byte);
    if ($parity % 2 == 0) {
	if ($ordbyte & 0x01) {
	    $ordbyte &= 0xFE;
	}
	else {
	    $ordbyte |= 0x01;
	}
    }
    return chr($ordbyte);
}

###########################################################################
# calc_resp computes the 24-bytes NTLM response based on the password hash
# and the nonce.
###########################################################################
sub calc_resp($$)
{
    my ($key, $nonce) = @_;
    my $cipher1;
    my $cipher2;
    my $cipher3; 
    usage("key must be 21-bytes long") unless length($key) == 21;
    usage("nonce must be 8-bytes long") unless length($nonce) == 8;
    if ($Authen::Perl::NTLM::PurePerl) {
	$cipher1 = Crypt::DES_PP->new(convert_key(substr($key, 0, 7)));
	$cipher2 = Crypt::DES_PP->new(convert_key(substr($key, 7, 7)));
	$cipher3 = Crypt::DES_PP->new(convert_key(substr($key, 14, 7)));
    }
    else {
	$cipher1 = Crypt::DES->new(convert_key(substr($key, 0, 7)));
	$cipher2 = Crypt::DES->new(convert_key(substr($key, 7, 7)));
	$cipher3 = Crypt::DES->new(convert_key(substr($key, 14, 7)));
    }
    return $cipher1->encrypt($nonce) . $cipher2->encrypt($nonce) . $cipher3->encrypt($nonce);
}

#########################################################################
# unicodify takes an ASCII string and turns it into a unicode string.
#########################################################################
sub unicodify($)
{
   my ($str) = @_;
   my $newstr = "";
   my $i;

   for ($i = 0; $i < length($str); ++$i) {
 	$newstr .= substr($str, $i, 1) . chr(0);
   }
   return $newstr;
}

##########################################################################
# UNIXTimeToFILETIME converts UNIX time_t to 64-bit FILETIME format used
# in win32 platforms. It returns two 32-bit integer. The first one is 
# the upper 32-bit and the second one is the lower 32-bit. The result is
# adjusted by cChallenge as in NTLM spec. For those of you who want to
# use this function for actual use, please remove the cChallenge variable.
########################################################################## 
sub UNIXTimeToFILETIME
{
    my ($time) = @_;
    $time = $time * 10000000 + 11644473600000000 + $Authen::Perl::NTLM::cChallenge;
    my $uppertime = $time >> 32;
    my $lowertime = $time & 0xffffffff;
    return ($lowertime & 0x000000ff, 
	    $lowertime & 0x0000ff00,
	    $lowertime & 0x00ff0000,
	    $lowertime & 0xff000000,
	    $uppertime & 0x000000ff,
	    $uppertime & 0x0000ff00,
	    $uppertime & 0x00ff0000,
	    $uppertime & 0xff000000);
}

1;

__END__

=head1 NAME

Authen::NTLM - Perl extension for NTLM related computations

=head1 SYNOPSIS

use Authen::NTLM qw(nt_resp lm_resp negotiate_msg auth_msg);

# To compose a NTLM Negotiate Packet
    $flags = Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_80000000 
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_128
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_NTLM
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_UNICODE
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM
	   | Authen::Perl::NTLM::NTLMSSP_REQUEST_TARGET;
    $negotiate_msg = negotiate_msg("my_domain", "my_ws", $flags);

# To compute the LM Response and NT Response based on password
    $my_pass = "mypassword";
    $lm_resp = lm_resp($my_pass, $nonce);
    $nt_resp = nt_resp($my_pass, $nonce);

# To compose a NTLM Response Packet
    $flags = Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_NTLM
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_UNICODE
	   | Authen::Perl::NTLM::NTLMSSP_REQUEST_TARGET;
    $auth_msg = auth_msg($lm_resp, $nt_resp, "my_userdomain", "my_username"
		"my_ws", "", $flags);

# To compute a nonce at the server side to create NTLM Challenge Packet
    $nonce = compute_nonce();

=head1 DESCRIPTION

The NTLM (Windows NT LAN Manager) authentication scheme is the authentication
algorithm used by Microsoft. 

NTLM authentication scheme is used in DCOM and HTTP environment. 
It is used to authenticate DCE RPC packets in DCOM. It is also used to
authenticate HTTP packets to MS Web Proxy or MS Web Server.

Currently, it is the authentication scheme Internet Explorer chooses to
authenticate itself to proxies/web servers that supports NTLM.

As of this version, NTLM module only provides the client side functions
to calculate NT response and LM response. The next revision will provide
the server side functions that computes the nonce and verify the NTLM responses.

This module was written without the knowledge of Mark Bush's (MARKBUSH)
NTLM implementation. It was used by Yee Man Chan to implement a Perl
DCOM client.

=head1 DEPENDENCIES

To use this module, please install the one of the following two sets of
DES and MD4 modules:

1) Crypt::DES module by Dave Paris (DPARIS) and Digest::MD4 module by 
Mike McCauley (MIKEM) first. These two modules are implemented in C.

2) Crypt::DES_PP module by Guido Flohr (GUIDO) and Digest::Perl::MD4
module by Ted Anderson (OTAKA). These two modules are implemented
in Perl.

The first set of modules will be preferred by NTLM because they are
supposedly faster.

=head1 TO-DO

1) A function to compose NTLM challenge packet for DCE RPC.

2) A function to parse NTLM negotiation packet for DCE RPC. 

3) A function to parse NTLM challenge packet for DCE RPC. 

4) A function to parse NTLM response packet for DCE RPC. 

5) A function to compute session key for DCE RPC.

6) Implement the module in C.

=head1 BUGS

Nothing known. The Makefile.PL in 0.02 has a "bug" that it 
can't pass CPAN's auto test program. It has been fixed. It
will work as expected for normal use though.

=head1 AUTHOR

This implementation was written by Yee Man Chan (ymc@yahoo.com).
Copyright (c) 2002 Yee Man Chan. All rights reserved. This program 
is free software; you can redistribute it and/or modify it under 
the same terms as Perl itself. 

=head1 SEE ALSO

Digest::MD4(3), Crypt::DES(3), perl(1), m4(1).

=cut

Local Variables:
mode: perl
perl-indent-level: 4
perl-continued-statement-offset: 4
perl-continued-brace-offset: 0
perl-brace-offset: -4
perl-brace-imaginary-offset: 0
perl-label-offset: -4
tab-width: 4
End:                                                                            
