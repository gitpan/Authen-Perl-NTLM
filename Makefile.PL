#!/usr/bin/perl

use ExtUtils::MakeMaker;
eval "require Crypt::DES && require Digest::MD4";
if ($@) {
    eval "require Crypt::DES_PP && require Digest::Perl::MD4";
    if ($@) {
	die "You haven't installed the required DES and/or MD4 modules!\n";
    }
    else {
	WriteMakefile(
	    'NAME'	    => 'Authen::Perl::NTLM',
	    'VERSION_FROM'  => 'lib/Authen/Perl/NTLM.pm',
	    'PREREQ_PM'     => {
			       Crypt::DES_PP => 1.00,
			       Digest::Perl::MD4 => 1.0, 
			       }
	);
    }
}
else {
    WriteMakefile(
	'NAME'		=> 'Authen::Perl::NTLM',
	'VERSION_FROM'	=> 'lib/Authen/Perl/NTLM.pm',
	'PREREQ_PM'     => {
			   Crypt::DES => 2.03,
			   Digest::MD4 => 1.1, 
			   }
);
}
