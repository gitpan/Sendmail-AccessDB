# t/03_functions.t; test the basic functions

$|++; 
print "1..5
";
my($test) = 1;

# 1 load
use Sendmail::AccessDB;
my $foo;

$Sendmail::AccessDB::DB_FILE="./t/test.db";
system("touch ./t/test.db");
system("/usr/sbin/makemap hash ./t/test < ./t/test");


my $friend = Sendmail::AccessDB::spam_friend('foo@bar.com');
if ( (defined $friend) and ($friend eq 'FRIEND')) 
  { print "ok $test\n";}else{ print "not ok $test\n"; }
$test++;

my $whitelisted = Sendmail::AccessDB::whitelisted('foo.test.example.com','type'=>'hostname');
if ( (defined $whitelisted) and ($whitelisted))
  { print "ok $test\n" }else{ print "not ok $test\n"; }
$test++;

my $should_fail = Sendmail::AccessDB::whitelisted('bar.example.com');
if ($should_fail) { print "not ok $test\n";} else { print "ok $test\n"; }
$test++;

my $lookup = Sendmail::AccessDB::lookup('foo.bar.tld','qualifier'=>'Qual');
if ( (defined $lookup) and ($lookup eq 'OK'))
   { print "ok $test\n" } else { print "not ok $test\n"; };
$test++;

my $wltwo = Sendmail::AccessDB::whitelisted('user@foo.bar.tld','qualifier'=>'Qual','type'=>'mail');
if ($wltwo) { print "ok $test\n" } else { print "not ok $test\n"; };
$test++;

# end of t/03_functions.t

