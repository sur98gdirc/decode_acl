
# subst-default-len.pm

use strict;
use warnings;

sub subst_seqn_len4(\%){
    my $rec = shift();
    no warnings qw(numeric);
    $rec->{seq_number} .= ' ' x (4 - length($rec->{seq_number}));
    }

sub subst_users_len10(\%){
    my $rec = shift();
    no warnings qw(numeric);
    $rec->{uid} .= ' ' x (10 - length($rec->{uid}));
    }

sub subst_inherit_len24(\%){
    my $rec = shift();
    no warnings qw(numeric);
    $rec->{inheritance} .= ' ' x (24 - length($rec->{inheritance}));
    }

( \&subst_seqn_len4 , \&subst_users_len10 , \&subst_inherit_len24 );

# EOF
