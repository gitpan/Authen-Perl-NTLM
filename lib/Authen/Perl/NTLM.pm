# -*- perl -*-
# NTLM.pm - An implementation of NTLM. In this version, I only
# implemented the client side functions that calculates the NTLM response.
# I will add the corresponding server side functions in the next version.
#

package Authen::Perl::NTLM;

use strict;
use Carp;
$Authen::Perl::NTLM::PurePerl = undef;
eval "require Crypt::DES && require Digest::MD4";
if ($@) {
    eval "require Crypt::DES_PP && require Digest::Perl::MD4";
    if ($@) {
	die "Required DES and/or MD4 module doesn't exist!\n";
    }
    else {
        $Authen::Perl::NTLM::PurePerl = 0;
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
@EXPORT_OK = qw (nt_resp lm_resp);
$VERSION = '0.01';

# Stolen from Crypt::DES.
sub usage {
    my ($package, $filename, $line, $subr) = caller (1);
    $Carp::CarpLevel = 2;
    croak "Usage: $subr (@_)";
}

sub lm_resp($$);
sub nt_resp($$);
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

1;

__END__

=head1 NAME

Authen::NTLM - Perl extension for NTLM related computations

=head1 SYNOPSIS

use Authen::NTLM qw(nt_resp lm_resp);

    $my_pass = "mypassword";
    $nt_resp = nt_resp($my_pass, $nonce);
    $lm_resp = lm_resp($my_pass, $nonce);

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

1) A function to compose NTLM negotiation packet for DCE RPC.

2) A function to compute nonce at the server side.

3) A function to compose NTLM chanllenge packet for DCE RPC.

4) A function to compose NTLM response packet for DCE RPC.

5) Implement the module in C.

=head1 BUGS

Nothing known.

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
