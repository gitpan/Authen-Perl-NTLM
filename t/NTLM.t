#!/usr/bin/perl

use Authen::Perl::NTLM qw(nt_resp lm_resp);
use Test;

plan tests => 2;
$my_pass = "Beeblebrox";
$nonce = "SrvNonce";
$correct_lm_resp = pack("H48", "ad87ca6defe34685b9c43c477a8c42d600667d6892e7e897");
$correct_nt_resp = pack("H48", "e0e00de3104a1bf2053f07c7dda82d3c489ae989e1b000d3");
$lm_resp = lm_resp($my_pass, $nonce);
ok($lm_resp eq $correct_lm_resp); 
$nt_resp = nt_resp($my_pass, $nonce);
ok($nt_resp eq $correct_nt_resp); 
