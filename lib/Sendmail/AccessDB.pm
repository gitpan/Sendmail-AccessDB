
package Sendmail::AccessDB;
use DB_File;
use strict;

BEGIN {
	use Exporter ();
	use vars qw ($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $regex_lock);
	$VERSION     = 0.03;
	@ISA         = qw (Exporter);
	#Give a hoot don't pollute, do not export more than needed by default
	@EXPORT      = qw ();
	@EXPORT_OK   = qw (spam_friend whitelisted);
	%EXPORT_TAGS = ();
}

=head1 NAME

Sendmail::AccessDB - An interface to the Sendmail access.db list

=head1 SYNOPSIS

 use Sendmail::AccessDB qw(spam_friend whitelisted);
 $friend_or_hater = spam_friend('user@example.com');
 $whitelisted = whitelisted('sender@example.com');

=head1 DESCRIPTION

This module is designed so that users of the Sendmail::Milter module (or
other Sendmail programmers) can ascertain if a user has elected to whitelist
themselves as a "spam friend" (where there should be no spam filtering on 
mail to them) or, where spam-filtering is not the default, but an option, where
certain receipients have been labeled as "spam haters"

=head1 USAGE

 use Sendmail::AccessDB qw(spam_friend);
 $friend_or_hater = spam_friend('user@example.com');

Ordinarily, this will look for such things as "Spam:user@example.com", 
"Spam:user@", etc., in the /etc/mail/access.db file. There is an optional
second argument "Category", which could be used if you wanted to enable 
specific checks, for example, if you wanted to customize down to a per-check
basis, you might use:

 $rbl_friend_or_hater = spam_friend('user@example.com','maps_rbl'); 
 $dul_friend_or_hater = spam_friend('user@example.com','maps_dul'); 

Caution should be taken when defining your own categories, as they may
inadvertantly conflict with Sendmail-defined categories.

 use Sendmail::AccessDB qw(whitelisted);
 $whitelisted = whitelisted('sender@example.com');
 $whitelisted_host = whitelisted('foo.example.com');
 $whitelisted_addr = whitelisted('192.168.1.123');

Would check for appropriate whitelisting entries in access.db.

=head1 BUGS

None that I've found yet, but I'm sure they're there.

=head1 SUPPORT

Feel free to email me at <dredd@megacity.org>

=head1 AUTHOR

	Derek J. Balling
	CPAN ID: DREDD
	dredd@megacity.org
	http://www.megacity.org/software.html

=head1 COPYRIGHT

Copyright (c) 2001 Derek J. Balling. All rights reserved.
This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=head1 SEE ALSO

perl(1).

=head1 PUBLIC METHODS

Each public function/method is described here.
These are how you should interact with this module.

=cut


=head2 spam_friend

 Usage     : $friend_or_hater = spam_friend($recipient,[$category])
 Purpose   : Consults the /etc/mail/access.db to check for spamfriendliness
 Returns   : 'friend','hater', or undef (which would mean default 
             behavior for that site)
 Argument  : The recipient e-mail address and an optional category if
             the default of 'Spam' is not desired. 
 Throws    : 
 Comments  : 
 See Also  : 

=cut

sub spam_friend
{
    my $address = shift;
    my $category = shift || 'Spam';
    my %access;
    tie %access,'DB_File', "/etc/mail/access.db";
    
    my @to_check = ("Spam:$address");
    {
        lock $regex_lock;
        my ($left,$right) = $address =~ /^(.*\@)(.*)/;
        push @to_check, ("$category:$left") if defined $left;
        push @to_check, ("$category:$right") if defined $right;
    }
    
    my $friend = 0; my $hater = 0;
    foreach my $dirty_check_me (@to_check)
    {
        my $check_me = lc $dirty_check_me;
        if (defined $access{$check_me})
        {
            if ( uc($access{$check_me}) eq 'FRIEND' )
            {
                $friend = 1;
            }
            if ( uc($access{$check_me}) eq 'HATER' )
            {
                $hater = 1;
            }
        }
    }

    if ($friend) { return 'FRIEND'; }
    if ($hater) { return 'HATER'; }
    return undef;
}

=head2 whitelisted

 Usage     : whitelisted($value)
 Purpose   : Determine if an e-mail address, hostname, or IP address is
             explicitly whitelisted
 Returns   : 0/1, true or false as to whether the argument is whitelisted
 Argument  : Either an email-address (e.g., foo@example.com), an IP address
             (e.g., 10.200.1.230), or a hostname (e.g., mailhost.example.com)
 Throws    : Nothing at present.
 Comments  : This is pretty new, use at your own risk :)
See Also   : 

=cut

sub whitelisted
{
    my $address = shift;
    my %access;
    tie %access, 'DB_File', "/etc/mail/access.db";
    
    my @to_check = ($address);
    my $RHS;
    {
        lock $regex_lock;
        if ($address =~ /^(.*)\@(.*)/)
        {
            my ($left,$right) = $address =~ /^(.*\@)(.*)/;
            push @to_check, ("$left") if defined $left;
            push @to_check, ("$right") if defined $right;
	    $RHS = $right if defined $right;
        }
        elsif ($address =~ /^(?:\d+\.){3}\d+/)
        {
            my $shorter = $address;
            $address =~ s/\.\d+$//;
            push @to_check, ($shorter);
            $address =~ s/\.\d+$//;
            push @to_check, ($shorter);
            $address =~ s/\.\d+$//;
            push @to_check, ($shorter);
        }       
        elsif ($address =~ /^[\w\-\.]+$/)
        {
            while (my ($shorter) = $address =~ /^[\w\-]+\.(.*)$/)
            {
                push @to_check, $shorter;
                $address = $shorter;
            }
        }
	if (defined $RHS)
	{
            while (my ($shorter) = $RHS =~ /^[\w\-]+\.(.*)$/)
            {
                push @to_check, $shorter;
                $RHS = $shorter;
            }
	}	    
    }
    my $ok = 0;
    foreach my $dirty_check_me (@to_check)
    {
        my $check_me = lc $dirty_check_me;
        if (defined $access{$check_me})
        {
            if ( uc($access{$check_me}) eq 'OK' )
            {
                $ok = 1;
            }
        }

    }

    return $ok;
}



=head1 PRIVATE METHODS

Each private function/method is described here.
These methods and functions are considered private and are intended for
internal use by this module. They are B<not> considered part of the public
interface and are described here for documentation purposes only.

(none)

=cut


1; #this line is important and will help the module return a true value
__END__


