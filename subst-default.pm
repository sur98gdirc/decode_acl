
# subst-default.pm

use strict;
use warnings;

sub subst_allow_deny(\%){
    my $rec = shift();
    $rec->{allow_deny} =~ s[ACCESS_ALLOWED_ACE_TYPE][ALLOW];
    $rec->{allow_deny} =~ s[ACCESS_DENIED_ACE_TYPE] [DENY ];
    }

sub subst_users_builtin(\%){
    my $rec = shift();
    $rec->{uid} =~ s[^BUILTIN\\admins$]  [\@admins];
    $rec->{uid} =~ s[^BUILTIN\\users$]   [\@users ];
    }

sub subst_inherit(\%){
    my $rec = shift();
    
    $rec->{inheritance} =~
s/          \[OBJECT_INHERIT_ACE\]
          \[CONTAINER_INHERIT_ACE\]
/[INHERIT] /;
    
    $rec->{inheritance} =~
s/          \[INHERITED_ACE\]
/[INHERITED] /;
    
    $rec->{inheritance} =~
s/          \[INHERIT_ONLY_ACE\]
/[INHERIT_ONLY]/;
    }

sub subst_perms_read(\%){
    my $rec = shift();
    $rec->{perms} =~ 
s/	FILE_LIST_DIRECTORY
	FILE_READ_ATTRIBUTES
	FILE_READ_EA
	FILE_TRAVERSE
	SYNCHRONIZE
	READ_CONTROL
/__READ_EXECUTE__\n/;
    }

sub subst_perms_all(\%){
    my $rec = shift();
    $rec->{perms} =~
s/	FILE_ALL_ACCESS
/__ALL__\n/;
    }

sub subst_perms_create(\%){
    my $rec = shift();
    $rec->{perms} =~ 
s/	FILE_ADD_FILE
	FILE_ADD_SUBDIRECTORY
/__CREATE_FILES_DIRS__\n/;
    }

( \&subst_allow_deny , \&subst_users_builtin , \&subst_inherit , 
    \&subst_perms_read , \&subst_perms_all , \&subst_perms_create );

# EOF
