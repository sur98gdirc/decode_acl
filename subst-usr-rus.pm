
# subst-usr-rus.pm

use strict;
use warnings;

sub subst_users_builtin_rus(\%){
    my $rec = shift();
    $rec->{uid} =~ s[^\?\?\?\s*$]                              [\@Everyone     ];
    $rec->{uid} =~ s[^NT AUTHORITY\\\?\?\?\?\?\?\?\s*$]        [\@SYSTEM       ];
    $rec->{uid} =~ s[^\?\?\?\?\?\?\?\?\?-\?\?\?\?\?\?\?\?\s*$] [\@CREATOR-OWNER];
    }

sub subst_users_len14(\%){
    my $rec = shift();
    no warnings qw(numeric);
    $rec->{uid} .= ' ' x (14 - length($rec->{uid}));
    }

( \&subst_users_builtin_rus , \&subst_users_len14 );

# EOF
