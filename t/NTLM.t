#!/usr/bin/perl

use Authen::Perl::NTLM qw(nt_hash lm_hash calc_resp negotiate_msg auth_msg compute_nonce);
use Test;

plan tests => 5;
$my_pass = "Beeblebrox";
$nonce = "SrvNonce";
$correct_negotiate_msg = pack("H74", "4e544c4d53535000" .
				"0100000007b200a00300030022000000" .
				"02000200200000005753444f4d");
$correct_lm_resp = pack("H48", "ad87ca6defe34685b9c43c477a8c42d600667d6892e7e897");
$correct_nt_resp = pack("H48", "e0e00de3104a1bf2053f07c7dda82d3c489ae989e1b000d3");
$correct_auth_msg = pack("H180", "4e544c4d5353500003000000" .
			"180018005a0000001800180072000000" .
			"0e000e0040000000080008004e000000" .
			"0400040056000000000000008a000000" .
			"05820000550053004500520044004f00" .
			"4d00550053004500520057005300") . 
			$correct_lm_resp . $correct_nt_resp;
    $flags = Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_80000000 
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_128
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_NTLM
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_UNICODE
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_OEM
	   | Authen::Perl::NTLM::NTLMSSP_REQUEST_TARGET;
    $negotiate_msg = negotiate_msg("DOM", "WS", $flags);
ok($negotiate_msg eq $correct_negotiate_msg);
$lm_hpw = lm_hash($my_pass);
$lm_resp = calc_resp($lm_hpw, $nonce);
ok($lm_resp eq $correct_lm_resp); 
$nt_hpw = nt_hash($my_pass);
$nt_resp = calc_resp($nt_hpw, $nonce);
ok($nt_resp eq $correct_nt_resp); 
   
    $flags = Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_NTLM
	   | Authen::Perl::NTLM::NTLMSSP_NEGOTIATE_UNICODE
	   | Authen::Perl::NTLM::NTLMSSP_REQUEST_TARGET;
    $auth_msg = auth_msg($lm_resp, $nt_resp, "USERDOM", "USER",
		"WS", "", $flags);
ok($auth_msg eq $correct_auth_msg);
$nonce = compute_nonce();
ok(length($nonce) == 8);
