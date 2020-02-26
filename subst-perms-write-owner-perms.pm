
# subst-perms-write-owner-perms.pm

use strict;
use warnings;

sub subst_perms_write_owner_perms(\%){
    my $rec = shift();
    $rec->{perms} =~
s/	READ_CONTROL
	WRITE_DAC
	WRITE_OWNER
$/__READ_WRITE_PERMS_OWNER__\n/;

    $rec->{perms} =~ 
s/	WRITE_DAC
	WRITE_OWNER
$/__WRITE_PERMS_OWNER__\n/;
    }

( \&subst_perms_write_owner_perms );

# EOF
