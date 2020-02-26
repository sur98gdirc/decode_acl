
# decode-acl.pl

use warnings;
use strict;

use Getopt::Std;
use FindBin(); BEGIN{ push @INC, $FindBin::Bin; }

my $help = "
usage:
$0  [ -x filter_module1,... ] 
    [ -n ] [ -s substituting_module1,... ]  file.accesschkout ...

if no input files specified then input is read from stdin

each of <filter_module>s must return a list of references to a funtion that
    takes a pathname and returns 1 (include), -1 (exclude) or 0(try next filter)
    if no decision was taken (e.g. no filter modules given) default is include

each of <substituting_module>s must return a list of references to a funtion 
    that takes a reference to a \%rec hash

-n - do not import default substituting modules: subst-default.pm 
    and subst-default-len.pm

";

my %options = ();
getopts("x:s:n",\%options)                      or die $help;
my $filter_modules           = $options{'x'};
my $subst_modules            = $options{'s'};
my $subst_no_default         = $options{'n'};

sub load_plugin($){
    my $file = shift;
    my @subroutines = do $file;
    unless ($subroutines[0]) {
        warn "couldn't parse $file: $@" if $@;
        warn "couldn't do $file: $!"    unless defined $subroutines[0];
        warn "couldn't run $file"       unless $subroutines[0];
        }
    return @subroutines;
    }

my @filter_modules = split /,/, $filter_modules;
my @filter_subroutunes = map { load_plugin($_); } @filter_modules;

my      @subst_modules = split /,/, $subst_modules;
unshift @subst_modules, 'subst-default.pm'      unless $subst_no_default;
push    @subst_modules, 'subst-default-len.pm'  unless $subst_no_default;
my @subst_subroutunes = map { load_plugin($_); } @subst_modules;

my $record = '';

sub process_record(){
    my %rec;
    unless  ( @rec{qw     (  seq_number    allow_deny         uid        inheritance         perms     )} 
            = $record =~ /^  (\[\d+\]) (ACCESS_\w+_ACE_TYPE): (.+)\n((?: {10}\[\w+\]\n)*)((?:\t\w+\n)+)$/ 
            ) {
        print "$0: invalid record\n";
        print $record;
        return;
        }
    
    foreach my $subst_fcn (@subst_subroutunes){
        $subst_fcn->(\%rec);
        }

    print "  $rec{seq_number} $rec{allow_deny} $rec{uid} $rec{inheritance} ", join (' ', split (' ', $rec{perms})), "\n";
    }

my $fl_now_skipping = 0;

while (<>){
    if (/^\S/) { # no spaces in the begining
        process_record() if $record;
        $record = '';
        
        while (/^Error: /) {
            my $error = $_;
            my $description = '';
            while(<>) {
                last if /^\S/; # no spaces in the begining
                $description .= $_;
                }
            if ($error =~ / has a non-canonical DACL:$/
                    and $description eq "   Inherited Deny after Inherited Allow\n" ){
                next; # false positive of error detection in accesschk
                }
            print $error;
            print $description;
            }
        
        my $pathname = $_;
        
        $fl_now_skipping = 0;
        foreach my $filter_fcn (@filter_subroutunes){
            my $res = $filter_fcn->($pathname);
            $fl_now_skipping = 1    if $res < 0;
            last                    if $res;
            }
        next    if $fl_now_skipping;

        print "\n";
        print $pathname;
        print "\n";
        }
    elsif (/^  \S/) { # two spaces in the begining
        next if $fl_now_skipping;
        process_record() if $record;
        $record = $_;
        }
    else{
        next if $fl_now_skipping;
        $record .= $_;
        }
    #print STDERR $record;
    }
process_record() if $record;

