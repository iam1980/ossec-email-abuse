#!/usr/bin/perl
#
# abuseEmail v1.1.2
# Finds out abuse email addresses for a specified IP address
# http://logidac.com/abuseEmail/
# 
# Created by Guillaume Filion <guillaume@filion.org>
# Copyright (C) 2001 Logidac enr.
#   				 16 Charles-Couillard
# 					 Beaumont, Quιbec
# 					 Canada, G0R 1C0
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Updated new reserved IP ranges 26/01/2013, mathiopoulos@gmail.com 

=head1 NAME

abuseEmail - Finds out abuse email addresses for a specified IP address

=head1 SYNOPSIS

B<abuseEmail> [B<OPTIONS>] I<ip-address>

=head1 DESCRIPTION

B<abuseEmail> receives an IP address and tries to find out, using its
internal whois and DNS clients, what is the responsible party's email
address. 

=head1 OPTIONS

=item B<--verbose i>

Set verbosity level to I<i>. The verbosity levels are:
0: silent, only output the result
1: same as 0 but also output fatal errors (default)
2: same as 1 but also output non-fatal errors 
5: The script will explain every action it makes. Set to 5 if you want to understand how abuseEmail works.

=item B<--noUseHostname>

Don't the hostname to guess some addresses. Depending on the severity of the attack, you may want to try
some simple guesses at abuse email addresses. For example, if you've just been portscanned by host.provider.com, 
writing to abuse@provider.com is a good idea. If you're being DoSed by an attacker, you may bypass the service provider and 
email directly to their uplink provider.

=item B<--noUseAbuseNet>

abuseEmail can passe all emails it founds into abuse.net whois service. For most domains, this founds the
right email address to report your problem. As for noUseHostname, you may want to desactivate this if you're reporting
an urgent problem.

=item B<--noUseDNSsoa>

Don't try to dig the IP subnet's manager email address using DNS SOA. You may want to desactivate this if you're reporting
something that is not urgent.

=item B<--noUseWhoisIP>

Don't use Whois to get IP addresses. This is really here for uniformity, since you almost always will want to use Whois.

=item B<--showCommands>

This is for educationnal use only. 8) This will show the unix equivalent command for every query made. That way, you can 
reproduce the technique used by abuseEmail.

=item B<--batch>

Outputs the result in a way that is easier to parse in a script. The output will look like: 127.123.123.123:abuse@mailprovider.com,roger@domain.top

=item B<--cache dir>

Use I<dir> as a cache directory for Whois queries.

=item B<--cacheExpire i>

Specify that cache entries should be used for I<i> seconds. Note that abuseEmail will not delete outdated cache entries.

You could set a cronjob like this to delete any file older than I<7> days in the I</your/cache/dir/> directory : I<find /your/cache/dir -mtime +7 -exec rm -f '{}' \;>
Never run this command as the superuser, you could end up deleting important things!

=head1 EXAMPLES

=item B<abuseEmail a.b.c.d>

The simplest way to use it. Will give a list of email addresses.

=item B<abuseEmail --cache=/tmp/abuseEmailcache --verbose=5 --showCommands a.b.c.d>

This is the best way of understanding how abuseEmail works and how to reproduce the results using
the regular Unix tools. We are using the I</tmp/abuseEmailcache> directory as a cache directory.

=item B<abuseEmail --noUseHostname --noUseAbuseNet a.b.c.d>

This could be used in case you really want to get infos about the uplink provided, not the service provider. You could use this
in an emergency situation.

In all those examples, I<a.b.c.d> must be replaced by a real IP address.


=head1 DIAGNOSTICS

=item Error: Please specify a host IP address.

(F) You did not specified an IP address to lookup. 

=item Error: This doesn't looks like a numeric IP address.

(F) Specifing an hostname will not work, a numeric IP address is required.

=item Error: %s is a private IP address (RFC1918). It's a local machine 
or a spoofed ip, either way, I can't give you any infos on this.

(F) Because of an IP address shortage, the IANA (Internet Assigned Numbers Authority),
decided to specify addresses that could only be used in private networks, not on the 
public Internet. You asked this program to lookup this kind of address, as it is a private 
address, it is not listed in any directory. You may want to ping this address to 
see if this come from a computer using a private address on your local network. It is 
also possible that the person who tried to connect to your computer sent a spoofed ip 
packet, that is, sending an ip packet with an incorrect "from:" tag. There is not much 
that you can do about this. Sorry.

=item Error: %s is a reserved IP address. It's very likely to be a spoofed ip, 
or your network admin/BOFH is on crack, either way, I can't give you any infos on this.

(F) The IP address you specified is a reserved address for experimental purposes; it is
almost impossible that such an IP address is used on the Net. What is very likely is that
the person who tried to connect to your computer sent a spoofed ip packet, that is, 
sending an ip packet with an incorrect "from:" tag. There is not much that you can do about
this. Sorry.


=head1 REQUIRES

Perl 5.004, Net::DNS, IO::Socket (included with Perl), Getopt::Long (included with Perl), XWhoisIP (included with abuseEmail)


=head1 SEE ALSO

dig(1), whois(1), perl(1), Net::DNS(3)


=head1 BUGS

Yes, there might be some. Please report any one you find to guillaume@filion.org

=head1 VERSION

Version 1.1.2, 2001-07-06

=head1 TODO

=item Better handling of the email addresses, and find out which one are best.

=item Dig the contact handles from whois and get email addresses from them.

=item Add support for rwhois servers (rwhois.arin.net, rwhois.verio.net, rwhois.exodus.net)

=item Remake everything in a more object oriented way and use XML for data.

=item Add an option to dig phone numbers.


=head1 WEBSITE

Visit B<http://logidac.com/abuseEmail/> for more infos and the lastest version.


=head1 AUTHOR

Guillaume Filion <guillaume@filion.org>

PGP Fingerprint: 14A6 720A F7BA 6C87 2331 33FD 467E 9198 3DED D5CA


=head1 THANKS

Great thanks to:

=item Russell Fulton who modified Net::XWhois to handle queries on IP addresses.

=item Philippe Bourcier of cyberabuse.org who provided me a list of 40 000 IPs with their relative abuse email address. Philippe also provided feedback on abuseEmail.

=cut


use strict;

package XWhoisIP;
## Net::XWhois
## Whois Client Interface Class. 
##
## $Date: 2001/03/19 $
## $Revision: 0.72-IP $
## $State: Exp $
## $Author: root $
##
## Copyright (c) 1998, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
## Modified on March 2001 by Russell Fulton to handle IP addresses.

#use Data::Dumper;
use IO::Socket; 
use Carp; 
use vars qw ( $VERSION $AUTOLOAD ); 

( $VERSION )  = '$Revision: 0.72 $' =~ /\s+(\d+\.\d+)\s+/; 

my $CACHE	 = ""; # "/tmp/whois"; 
my $EXPIRE   = 0; # 604800 
my $ERROR    = "croak"; 
my $TIMEOUT  = 60;

my %PARSERS  = ( 

ARIN => {
        netname => 'etname:\s*(\S+)\n+',
        netblock => 'etblock:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\n\s]*',
        netnumber => 'Netnumber:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\n\s]*',
        hostname => 'Hostname:\s*(\S+)[\n\s]*',
        maintainer => 'Maintainer:\s*(\S+)',
        record_update => 'Record last updated on (\S+)\.\n+',
        database_update => 'Database last updated on (.+)\.[\n\s]+The',
        registrant => '^(.*?)\n\n',
        results => \&get_results,
        reverse_mapping => 'Domain System inverse[\s\w]+:[\n\s]+(.*?)\n\n',
        coordinator => 'Coordinator:[\n\s]+(.*?)\n\n',
        coordinator_handle =>'Coordinator:[\n\s]+[^\(\)]+\((\S+?)\)',
        contact_emails => 'Coordinator:[\n\s]+(.*?)\n\n',
        address => 'Address:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        system => 'System:\s+([^\n]*)\n',
        non_portable => 'ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE',
},

APNIC => {
        netnumber => 'inetnum:\s+(.+)\n',
        netname => 'etname:\s*(\S+)\n',
        country => 'country:\s+(\S+)\n',
        admin_contact => 'admin-c:\s*(\S+)\n',
        tech_contact => 'tech-c:\s*(\S+)\n',
		contact_emails  => 'e-mail:\s+(\S+\@\S+)', 
		contact_emails_a  => 'changed:\s+(\S+\@\S+)', 
        source => 'source:\s*(\S+)\n',
},

BRAZIL => {
        netnumber => 'inetnum:\s+(.+)\n',
        netname => 'owner:\s+(.+)\n',
        country => 'country:\s+(\S+)\n',
        admin_contact => 'admin-c:\s*(\S+)\n',
        tech_contact => 'tech-c:\s*(\S+)\n',
        abuse_contact => 'abuse-c:\s*(\S+)\n',
		contact_emails  => 'e-mail:\s+(\S+\@\S+)', 
        source => 'source:\s*(\S+)\n',
},

ABUSE => {
        content => \&get_content,
},

INTERNIC => {    
  name            => 'omain Name:\s+(\S+)', 
  status          => 'omain Status:\s+(.*?)\s*\n', 
  nameservers     => 'in listed order:[\s\n]+(\S+)\s.*?\n\s+(\S*?)\s.*?\n\n',
  registrant      => 'Registrant:\s*\n(.*?)\n\n',
  contact_admin   => 'nistrative Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_tech    => 'Technical Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_zone    => 'Zone Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_billing => 'Billing Contact.*?\n(.*?)(?=\s*\n[^\n]+?:\s*\n|\n\n)',
  contact_emails  => '(\S+\@\S+)',
  contact_handles => '\((\w+\d+)\)',
  domain_handles  => '\((\S*?-DOM)\)',
  org_handles     => '\((\S*?-ORG)\)',
  not_registered  => 'No match',
  forwardwhois    => 'Whois Server: (.*?)(?=\n)',
}, 

INTERNIC_CONTACT => { 
  name            => '(.+?)\s+\(.*?\)(?:.*?\@)',
  address         => '\n(.*?)\n[^\n]*?\n\n\s+Re',
  email           => '\s+\(.*?\)\s+(\S+\@\S+)',
  phone           => '\n([^\n]*?)\(F[^\n]+\n\n\s+Re',
  fax             => '\(FAX\)\s+([^\n]+)\n\n\s+Re',
 }, 

CANADA  => {
  name            => 'domain:\s+(\S+)\n',
  netname         => 'netname:\s+((\S+)\n',
  nameservers     => '-Netaddress:\s+(\S+)',
  contact_emails  => '-Mailbox:\s+(\S+\@\S+)',
 },


 RIPE => { 
  name            => 'domain:\s+(\S+)\n', 
  netname 		  => 'etname:\s*(\S+)\n',
  nameservers     => 'nserver:\s+(\S+)', 
  contact_emails  => 'notify:\s+(\S+\@\S+)', 
  contact_emails_a  => 'e-mail:\s+(\S+\@\S+)', 
  registrants     => 'descr:\s+(.+?)\n',
 }, 

 RIPE_CH => { 
  name            => 'domainname:\s+(\S+)\n', 
  nameservers     => 'nserver:\s+(\S+)', 
  contact_emails  => 'e-mail:\s+(\S+\@\S+)', 
 }, 

 JAPAN => { 
  name            => '\[Domain Name\]\s+(\S+)',
  nameservers     => 'Name Server\]\s+(\S+)', 
  contact_emails  => '\[Reply Mail\]\s+(\S+\@\S+)',
  netname         => '\s+([^\n]\n)',
 },

 TAIWAN => { 
  name            => 'omain Name:\s+(\S+)', 
  netname => 'etname:\s*(\S+)\n',
  registrant      => '^(\S+) \(\S+?DOM)',
  contact_emails  => '(\S+\@\S+)',
  nameservers     => 'servers in listed order:[\s\n]+\%see\-also\s+\.(\S+?)\:',
 },

 KOREA  => {
  name            => 'Domain Name\s+:\s+(\S+)',
  netname         => 'Name  \s+:\s+(\S+)',
  nameservers     => 'Host Name\s+:\s+(\S+)',
  contact_emails  => 'E\-Mail\s+:\s*(\S+\@\S+)',
 },

 GENERIC => { 
  contact_emails  => '(\S+\@\S+)',
 }, 
 

);

my %ASSOC = (   

 'whois.arin.net'       => [ "ARIN",  [ qw/IP/ ] ],
 'whois.apnic.net'      => [ "APNIC",  [  ] ],
 'whois.nic.br'         => [ "BRAZIL",  [  ] ],
 'whois.abuse.net'		=> [ "ABUSE",  [  ] ],
 'whois.internic.net'   => [ "INTERNIC",  [ qw/com net org edu/ ] ],
 'whois.nic.gov'        => [ "INTERNIC",  [ qw/gov/ ] ],
 'whois.nic.mil'        => [ "INTERNIC",  [ qw/mil/ ] ],
 'whois.isi.edu'        => [ "INTERNIC",  [ qw/us/  ] ],
 'whois.nic.net.sg'     => [ "RIPE",      [ qw/sg/  ] ],
 'whois.aunic.net'      => [ "RIPE",      [ qw/au/  ] ],  
 'whois.nic.ch'         => [ "RIPE_CH",   [ qw/ch/  ] ], 
 'whois.nic.uk'         => [ "INTERNIC",  [ qw/uk/  ] ], 
 'whois.nic.ad.jp'      => [ "JAPAN",     [ qw/jp/  ] ], 
 'whois.twnic.net'      => [ "TAIWAN",    [ qw/tw/  ] ], 
 'whois.krnic.net'      => [ "KOREA",     [ qw/kr/  ] ], 
 'whois.domainz.net.nz' => [ "GENERIC",   [ qw/nz/  ] ],
 'cdnnet.ca'            => [ "CANADA",    [ qw/ca/  ] ],
 'whois.ripe.net'       => [ "RIPE",      [ 
                        qw( al am at az      ma md mk mt  
                            ba be bg by      nl no        
                            ch cy cz         pl pt        
                            de dk dz         ro ru        
                            ee eg es         se si sk sm su 
                            fi fo fr         tn tr 
                            gb ge gr         ua uk
                            hr hu ie         va
                            il is it         yu
                            li lt lu lv 
                          ) ] ], 
);


my %ARGS = (
    'whois.nic.ad.jp'            => { 'S' => '/e' },
    'whois.internic.net'         => { 'P' => '=' },
    'whois.networksolutions.com' => { 'P' => '=' },
); 

sub get_results {

   my $ippat = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';  # re to match IP

   my $result;

   my @results;

   foreach  (split ("\n", shift )) {
      chomp;
      if( /^\s/ ) { $result .= " $_"; }
      else { 
	 if( defined $result ) {
	    my($name, $handle, $netblock) =
	       $result =~ /^(.+)\(([^)]+)\)\s*
		  [-A-Z0-9]+\s+($ippat\s+-\s+$ippat)/x ;
	    push(@results, join("\t", $name, $handle, $netblock) )
	       if defined $name;

         }
	 $result = $_;
      } 
   }

   return @results;
}

sub get_content {
	my $content = shift;
	return $content;
}

sub register_parser { 

    my ( $self, %args ) = @_;

    $self->{ _PARSERS }->{ $args{ Name } } = {} unless $args{ Retain }; 
    for ( keys %{ $args{ Parser } } ) { 
        $self->{ _PARSERS }->{ $args{ Name } }->{$_} = $args{ Parser }->{$_}; 
    }

    return 1;     
    
} 


sub register_association { 

    my ( $self, %args ) = @_; 
    for ( keys %args ) { $self->{ _ASSOC }->{ $_ } = $args{ $_ } };
    return 1; 

}


sub register_cache { 

    my ( $self, $cache ) = @_; 
    return ${ $self->{ _CACHE } } = $cache  if $cache;

}


sub guess_server_details { 

    my ( $self, $domain ) = @_;
    $domain = lc $domain;

    my ( $server, $parser ); 
    my ( $Dserver, $Dparser ) = 
       ( 'whois.internic.net', { %{ $self->{ _PARSERS }->{ INTERNIC } } } );

    SWITCH: for ( keys %{ $self->{ _ASSOC } } ) { 
        if ( grep { $domain =~ m/\.$_$/ } @{ $self->{ _ASSOC }->{ $_ }[1] } ) { 
            $server = $_; 
            $parser = $self->{ _PARSERS }->{ $self->{ _ASSOC }->{ $_ }[0] };
            last SWITCH; 
         }
     }

    return $server ? [$server, $parser] : [$Dserver, $Dparser]; 

};


sub new { 

    my ( $class, %args ) = @_; 

    my $self = {}; 
    $self->{ _PARSERS } = \%PARSERS; 
    $self->{ _ASSOC }   = \%ASSOC; 
    $self->{ _CACHE }   = $args{Cache}; 
    $self->{ _EXPIRE }  = $args{Expire};
    $self->{ _ARGS }    = \%ARGS;

    bless $self, $class; 

    $self->personality ( %args ); 
    $self->lookup () if $self->{ Domain };
    return $self; 

}


sub personality { 

    my ( $self, %args ) = @_; 

    for ( keys %args ) { chomp $args{ $_}; $self->{ $_ } = $args{ $_ } } 
    $self->{ Parser } = $self->{ _PARSERS }->{ $args{ Format } } 
                        if $args{ Format };
    
    unless ( $self->{ Server } ) { 
        my $res = $self->guess_server_details ( $self->{ Domain } ); 
        ( $self->{ Server }, undef ) = @$res; 
   }

    if( $ASSOC{$self->{ Server }} ) {  # added rjf 20/3/01
       $self->{ Format } = $ASSOC{$self->{ Server }}->[0];
       $self->{ Parser } =  $self->{ _PARSERS }->{$self->{ Format }};
    }

    unless ( $self->{ Parser } &&  $self->{ Format } ) { 
        my $res = $self->guess_server_details ( $self->{ Domain } ); 
        ( undef, $self->{ Parser } ) = @$res; 
    }

    $self->{ Timeout } = $TIMEOUT unless $self->{ Timeout };
    $self->{ Error }   = $ERROR unless $self->{ Error };

}


sub lookup { 

    my ( $self, %args ) = @_;

    $self->personality ( %args ); 

    my $cache = $args{ Cache } || ${ $self->{ _CACHE } }; 
    my $domain = $self->{ Domain }; 
    my $server = $self->{ Server }; 

	#print "lookup is using cache: $cache\n";

    unless ( $self->{ Nocache } ) { 
    READCACHE: { 
        if ( $cache and  -d $cache ) {
            last READCACHE unless -e "$cache/$domain-$server";
            my $current = time ();  
            open D, "$cache/$domain-$server" || last READCACHE; 
            my @stat = stat ( D ); 
            if ( $current - $stat[ 9 ] > ${ $self->{ _EXPIRE } } ) { 
                close D; 
                last READCACHE; 
            }
            undef $/; $self->{ Response } = <D>; 
            return 1; 
        } 
    }
    }

    my $suffix = $self->{ _ARGS }->{ $server }->{S} || ''; 
    my $prefix = $self->{ _ARGS }->{ $server }->{P} || ''; 
    my $sock = $self->_connect ( $self->{ Server } ); 
    return undef unless $sock;
    print $sock $prefix , $self->{ Domain }, "$suffix\r\n"; 
    { local $/; undef $/; $self->{  Response  } = <$sock>; }  
    undef $sock;

    my $fw = eval { $self->forwardwhois };

    my @fwa = ();
    if (defined $fw and $fw =~ m/\n/) {
        @fwa = $self->{ Response} =~ 
        m/\s+$self->{ Domain }\n.*?\n*?\s*?.*?Whois Server: (.*?)(?=\n)/isg;
        $fw = shift @fwa;
		return undef unless (length($fw) > 0); # pattern not found
            return undef if ($self->{ Server } eq $fw); #avoid infinite loop
    }       
    if (defined $fw and $fw ne "" ) { 
        $self->personality( Format => $self->{_ASSOC}->{$fw}->[0]);
        $self->{ Server } = $fw; $self->{ Response } = "";
        $self->lookup(); 
    }

    if ( $cache and (-d $cache) && (!($self->{Nocache})) ) { 
        open D, "> $cache/$domain-$server" || return; 
        print D $self->{ Response }; 
        close D; 
    } 

}


sub AUTOLOAD { 

    my $self = shift; 

    return undef unless $self->{ Response }; 

    my $key = $AUTOLOAD; $key =~ s/.*://; 

    croak "Method $key not defined." unless exists ${$self->{ Parser }}{$key};

    my @matches = ();

    if ( ref(${$self->{ Parser } }{ $key }) !~ /^CODE/  ) {
	@matches = $self->{ Response } =~ /${ $self->{ Parser } }{ $key }/sg; 
    } else {
        @matches = &{ $self->{ Parser }{$key}}($self->response);
    }
 
    my @tmp = split /\n/, join "\n", @matches; 
    for (@tmp) { s/^\s+//; s/\s+$//; chomp };  

    return wantarray ? @tmp :  join "\n", @tmp ;  

}


sub response { 

    my $self = shift; 
    return $self->{ Response }; 

}


sub _connect {
 
    my $self = shift; 
    my $machine = shift; 
    my $error = $self->{Error};

    my $sock = new IO::Socket::INET PeerAddr => $machine,
                                    PeerPort => 'whois',
                                    Proto    => 'tcp',
                                    Timeout  => $self->{Timeout}
       or &$error( "[$@]" );

    $sock->autoflush if $sock;
    return $sock;

}    


sub ignore {}

'True Value.';



######################## end of Xwhois ##########################
## This is abuseEmail:

package main;

use IO::Socket ();
use Getopt::Long ();
use Net::DNS;
#use XWhoisIP;

#####
# Options:
#

# Location of abuseEmail's blacklist, for example: /etc/abuseEmail.blacklist
my $blacklist="";

# Cache directory
# abuseEmail can cache the data it founds so that you can speed it up a little.
# expire is the number of seconds the cache should be considered usefull.
$main::cachedir="";
$main::cacheexpire=7 * 24 * 3600; # one week in klingon time, also in unix time.

# Verbose level:
# 0: silent, only output the result
# 1: same as 0 but also output fatal errors (default)
# 2: same as 1 but also output non-fatal errors 
# 5: noisy: explain every action
$main::verbose=1; #default

# Use the hostname to guess some addresses
# 0: no 				--noUseHostname
# 1: yes (default)		--useHostname
$main::useHostname=1; #default

# Pass all the email addresses found into abuse.net directory
# 0: no					--noUseAbuseNet
# 1: yes (default)		--useAbuseNet
$main::useAbusenet=1; #default

# Dig the subnet manager's email address using DNS SOA
# 0: no					--noUseDNSsoa
# 1: yes (default)      --useDNSsoa
$main::useDNSsoa=1; #default

# Get some system managers's email addresses using Whois on the IP address
# 0: no					--noUseWhoisIP
# 1: yes (default)      --useWhoisIP
$main::useWhoisIP=1; #default

# Show the Unix shell equivalent of every action taken (so the user can reproduce the technique).
# 0: no (default)		--noShowCommands
# 1: yes				--showCommands
$main::showCommands=0; #default

# Batch mode, outputs something like:
# 127.123.123.123:abuse@mailprovider.com, roger@domain.top
$main::batch=0; #default

# Modification of the default options by the long args. 
Getopt::Long::GetOptions(	
	"verbose=i" 	=> \$main::verbose, 
	"usehostname!" 	=> \$main::useHostname,
	"useabusenet!" 	=> \$main::useAbusenet,
	"usednssoa!"	=> \$main::useDNSsoa,
	"usewhoisip!"	=> \$main::useWhoisIP,
	"showcommands!"	=> \$main::showCommands,
	"batch!"		=> \$main::batch,
	"cache=s"		=> \$main::cachedir,
	"cacheexpire=i"	=> \$main::cacheexpire,
	"help!"			=> \$main::showHelp,
);

if ($main::showHelp) {
	printUsage();
	exit(0);
}

#
###################

my $ip = shift || die "Error: Please specify a host IP address.\n";
die "Error: This doesn't looks like a numeric IP address.\n" unless isIP($ip);

# Structure of @main::abuseEmails: [email_address, confidence]
@main::abuseEmails=();

# Blacklist
# The blacklist can contains an unlimited number of entries.
# Each entry is a general expression, one entry per line
# Blanks lines and commented lines (#) don't count
# Optimisation: Keep the most frequent entries at the top of the list, Keep the list short
@main::blist=();

# Checking if it's a Private ip address
print "Checking if $ip is a Private ip address..." if ($main::verbose>=5);
if ( # RFC1918
   between("192.168.0.0",$ip,"192.168.255.255")		# IANA-CBLK1
|| between("172.16.0.0",$ip,"172.31.255.255")		# IANA-BBLK-RESERVED
|| between("10.0.0.0",$ip,"10.255.255.255")			# RESERVED-6, RESERVED-10
) {
	print "\nError: $ip is a private IP address (RFC1918). It's a local machine or a spoofed ip, either way, I can't give you any infos on this.\n" if ($main::verbose>=1);
	exit(1);
}
print "no\n" if ($main::verbose>=5);

# Checking if it's a reserved ip address
print "Checking if $ip is a reserved ip address..." if ($main::verbose>=5);
if (
   # IANA reserved -- This list will need to be updated from time to time.
   # http://archives.neohapsis.com/archives/snort/2000-03/0428.html
   # http://www.iana.org/assignments/ipv4-address-space
   between("0.0.0.0",$ip,"0.255.255.255")			# RESERVED-1
#|| between("1.0.0.0",$ip,"1.255.255.255")			# RESERVED-9
#|| between("2.0.0.0",$ip,"2.255.255.255")			# RESERVED-2
|| between("10.0.0.0",$ip,"10.255.255.255")			# RESERVED-5
#|| between("14.0.0.0",$ip,"14.255.255.255")			# NET-PDN
#|| between("23.0.0.0",$ip,"23.255.255.255")			# RESERVED-23
#|| between("27.0.0.0",$ip,"27.255.255.255")			# RESERVED-27
#|| between("31.0.0.0",$ip,"31.255.255.255")			# RESERVED-12, RESERVED-31
#|| between("36.0.0.0",$ip,"36.255.255.255")			# RESERVED-36
#|| between("37.0.0.0",$ip,"37.255.255.255")			# RESERVED-37
#|| between("39.0.0.0",$ip,"39.255.255.255")			# RESERVED-39A
#|| between("41.0.0.0",$ip,"41.255.255.255")			# RESERVED-41A
#|| between("42.0.0.0",$ip,"42.255.255.255")			# RESERVED-42
#|| between("58.0.0.0",$ip,"60.255.255.255")			# RESERVED-58, RESERVED-59, RESERVED-60
#|| between("67.0.0.0",$ip,"79.255.255.255")			# RESERVED-7
#|| between("82.0.0.0",$ip,"95.255.255.255")			# RESERVED-11
|| between("100.64.0.0",$ip,"100.127.255.255")		# RESERVED-8
|| between("127.0.0.0",$ip,"127.255.255.255")		# LOOPBACK
#|| between("128.0.0.0",$ip,"128.0.255.255")			# RESERVED-3
|| between("169.254.0.0",$ip,"169.254.255.255")		# LINKLOCAL
|| between("172.16.0.0",$ip,"172.31.255.255")		# RESERVED-4
|| between("192.0.0.0",$ip,"192.0.0.7")		# RESERVED-13
|| between("192.0.2.0",$ip,"192.0.2.255")		# RESERVED-14
|| between("192.168.0.0.",$ip,"192.168.255.255")		# RESERVED-5
|| between("198.18.0.0",$ip,"198.19.255.255")		# MCAST-NET (CLASS D MULTICAST)
|| between("203.0.113.0",$ip,"203.0.113.255")		# IANA - Reserved (CLASS Experimental)
|| between("224.0.0.0",$ip,"239.255.255.255")
|| between("240.0.0.0",$ip,"255.255.255.254")
|| between("255.255.255.255",$ip,"255.255.255.255")
) {
	print "\nError: $ip is a reserved IP address. It's very likely to be a spoofed ip, or your network admin/BOFH is on crack, either way, I can't give you any infos on this.\n" if ($main::verbose>=1);
	exit(1);
}
print "no\n" if ($main::verbose>=5);


# Loading the blacklist
if ($blacklist) {
   print "Loading the blacklist..." if ($main::verbose>=5);
   open (BLIST, $blacklist) || die "Can't open the blacklist file ($blacklist): $.\n";
   while (my $data = <BLIST>) {
        chomp $data;
        push (@main::blist, $data) if ($data and not(substr($data,0,1) eq '#'));
   }
   close BLIST;
   print "loaded with ".@main::blist." items.\n" if ($main::verbose>=5);
}


# Check IP's hostname
my $hostname="";
if ($main::useHostname) {
	print "Checking the hostname associated with $ip... " if ($main::verbose>=5);
	$hostname = ip2host($ip);
	do {print (($hostname)?"$hostname":"none")} if ($main::verbose>=5);
	if ($hostname && (host2ip($hostname) ne $ip)) {
		# Hum, Paranoid reverse DNS didn't passed, I don't trust this hostname
		print " Hum, Paranoid reverse DNS didn't passed, I don't trust this hostname" if ($main::verbose>=5);
		$hostname="";
	}
	print "\n" if ($main::verbose>=5);
	
	# Checking directly at abuse.net for this hostname
	if ($hostname and $main::useAbusenet) {
		print "\nChecking directly at abuse.net for this hostname..." if ($main::verbose>=5);
		whoisAbuseAddList($hostname,1);
	}
	print "\n" if ($main::verbose>=5);
}

# Checking DNS zone's SOA
if ($main::useDNSsoa) {
	print "Checking DNS zone's Start of Authority " if ($main::verbose>=5);
	my $soa;

	# SOA on the hostname
	if ($hostname && $main::loose) { 
		# We don't have enough confidence in the addresses we allready got, trying to find more...
		print "on the hostname...\n" if ($main::verbose>=5);
		my $nsname="a.".$hostname;
		while ($nsname=popByte($nsname)) {
			$soa=DNSsoa($nsname);
			last if $soa;
		}
		if ($soa) {
			print "found: $soa\n" if ($main::verbose>=5);
			AddEmailList(soaToEmail($soa),0);
		} else {
			print "not found.\n" if ($main::verbose>=5);
		}
	} 

	# SOA on ip address
	# This will usually give use emails of upstream providers
	print "on the ip address..." if ($main::verbose>=5);
	$soa="";
	my $nsname="a.".inaddr($ip);
	while ($nsname=popByte($nsname)) {
		$soa=DNSsoa($nsname);
		#print "soa: $soa\n";
		last if $soa;
	}
	if ($soa) {
		print "found: $soa\n" if ($main::verbose>=5);
		AddEmailList(soaToEmail($soa),0);
	} else {
		print "not found.\n" if ($main::verbose>=5);
	}

}

if ($main::useWhoisIP) {
	print "Checking with ARIN/APNIC/RIPE/AUSNIC/etc..." if ($main::verbose>=5);
	# Checking with ARIN/APNIC/RIPE/AUSNIC
	do_whois('whois.arin.net', $ip);
}

# Done!
# Print the emails found with their confidence
print "\nFound these abuse addresses:\n" if ($main::verbose>=5);
print "Email address\tConfidence (the more, the better)\n" if (($main::verbose>=5) and not ($main::batch));

# Sort the emails by order of confidence.
my @emailList = sort {@{$b}[1] <=> @{$a}[1]} @main::abuseEmails;
my $emlist if $main::batch;

foreach my $foo (@emailList) {
	if ($main::batch) {
		# Batch mode. Output looks like:
		# 127.123.123.123:abuse@mailprovider.com,roger@domain.top
		$emlist = $emlist . @{$foo}[0] . ",";
	} else {
		# Normal mode. Output looks like:
		# abuse@mailprovider.com	2
		# roger@domain.top	1
		print @{$foo}[0] ."\t". @{$foo}[1] ."\n";
	}
}
if ($main::batch) {
	chop $emlist; # remove the trailing comma.
	print $ip .":". $emlist ."\n";
}

exit(0);
################################### SUB ROUTINES ###################################################
## DNS functions
sub ip2host {
	my $foo;
	my $ip = shift;
	if (isIP($ip)) {	
		my @aa = split('\.', $ip);  
		my $aaa = pack('C4', @aa);
		$foo = gethostbyaddr($aaa,2);
	}
	print "host $ip\n" if $main::showCommands;
	return $foo;
}

sub host2ip {
	my $host = shift;
	my ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($host);
	my ($a,$b,$c,$d) = unpack('C4',$addrs[0]);
	print "host $host\n" if $main::showCommands;
	return "$a\.$b\.$c\.$d";
}

sub DNSsoa { 
	my $domain = shift;
	my $soa="";
	
	# Check if it's allready in cache.
	# DNSsoa cache is disabled at the moment.
	# Remove the "0 and " in the if to reactivate it...
    READCACHE: { 
        if ( 0 and $main::cachedir and (-d $main::cachedir) ) {
            last READCACHE unless -e "$main::cachedir/$domain-dnssoa";
            my $current = time ();  
            open D, "$main::cachedir/$domain-dnssoa" || last READCACHE; 
            my @stat = stat ( D ); 
            if ( $current - $stat[ 9 ] > $main::cacheexpire ) { 
                close D; 
                last READCACHE; 
            }
            undef $/; $soa = <D>; 
            return $soa; 
        } 
    }
	
	# It's not, check using Net::DNS
	my $res = eval { new Net::DNS::Resolver };
	return unless $res; 
	my $query = $res->query($domain, "SOA");
	$soa = ($query->answer)[0]->rname if ($query);
	
	print "dig $domain soa\n" if $main::showCommands;
	
	# Save it to cache
	if ( 0 and $main::cachedir and (-d $main::cachedir) ) {
        open D, "> $main::cachedir/$domain-dnssoa" || return; 
        print D $soa; 
        close D; 
    } 
	
	return $soa;
}

# Takes 192.168.0.4 and returns 4.0.168.192.in-addr.arpa
sub inaddr {
	my $ip = shift;
	my $inaddr;
	if ($ip =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/) {
		$inaddr = "$4\.$3\.$2\.$1\.in-addr.arpa";
	}
	return $inaddr;
}

## Misc functions
# Return true if a string is empty or contains things of little interest.
sub empty {
	$a = shift;
	return 1 unless $a;
	return (($a ne "\n") && not($a =~ /\s/)) ;
}

# Finds out the domain of an email address
sub emailDomain {
	$a = shift;
	($a =~ /.+\@(.+)/);
	return $1;
}

## IP addresses manipulations functions
# Checks if this is really an ip address
sub isIP {
	my $ip = shift;
	return ( ($ip =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/) and 
		$1<256 and $2<256 and $3<256 and $4<256 );
}

# Transforms an ip address to a decimal number
sub ip2dec { 
	my ($ip) = shift;
	my $dec=0;
	if ( ($ip =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/) and 
		$1<256 and $2<256 and $3<256 and $4<256 
	) {
		$dec = $1*(16777216) + $2*(65536) + $3*(256) + $4*(1);
	}
	return $dec;
}

# Transforms a decimal number to an ip address
sub dec2ip {
	my ($dec) = shift;
	return 0 if ($dec>0 or $dec<4294967295);
	
	my @ip;
	$ip[0]=$dec/16777216;
	$ip[1]=($ip[0]-int($ip[0]))*16777216/65536;
	$ip[2]=($ip[1]-int($ip[1]))*65536/256;
	$ip[3]=($ip[2]-int($ip[2]))*256/1;
	return (int($ip[0]),"\.",int($ip[1]),"\.",int($ip[2]),"\.",int($ip[3]));
}

# $a > $b
sub greater {
   my ($a,$b) = @_;
   return (ip2dec($a) > ip2dec($b));
}

# $a < $b
sub smaller {
   my ($a,$b) = @_;
   return (ip2dec($a) < ip2dec($b));
}

# $a <= $ip <= $b
sub between {
	my ($a,$ip,$b) = @_;
	return ((ip2dec($a) <= ip2dec($ip)) && (ip2dec($ip) <= ip2dec($b)));
}

# Remove the first byte of an ip address (in fact, removes everything before the first period).
sub popByte {
	my $a = shift;
	($a =~ /.+?\.(.+)/);
	return $1;
}

sub soaToEmail { my $soa = shift;
	if ($soa =~ /([^\.]+)\.(.+)/) {
		return $1."\@".$2;
	} else {
		return "";
	}
}

# Returns true if the email is on the blacklist
sub blacklisted {
	my $e = shift;
	my $blisted=0;
	
	foreach my $entry (@main::blist) {
		if ($entry && ($e =~ /$entry/)) {
			$blisted=1;
			last;
		}
	}
	
	return $blisted;
}

sub AddEmailList {
	my ($query,$strict) = shift;
	
	if ($main::useAbusenet) {
		whoisAbuseAddList( emailDomain($query), $strict);
	} elsif (not blacklisted($query)) {
		addToList($query);
	} else {
		print "this email is blacklisted: refused." if ($main::verbose>=5);
	}
	print "\n" if ($main::verbose>=5);

}

## Whois functions
# Very high level function that queries whois.abuse.net with a domain name and adds the result to the list.
sub whoisAbuseAddList {

	my ($query,$strict) = shift;

	print "whois -h whois.abuse.net $query\n" if $main::showCommands;
	my $w = eval { new XWhoisIP ( 
		Server => "whois.abuse.net",	Domain => $query,
		Cache  => \$main::cachedir,		Expire => \$main::cacheexpire
		) 
	};
   	return unless $w;
	#my @abuse = split(/\n/, whois("whois.abuse.net", $query) );
	my @abuse = split(/\n/, $w->content() );
	undef $w;

	foreach my $address (@abuse) {
		if ($address =~ /([^\s]+\@[^\s]+)/) {
			my $possibleEmail=$1;
			if (not($strict) or ($hostname =~ emailDomain($possibleEmail)) ) {
				print "found $possibleEmail\n" if ($main::verbose>=5);
				
				# Checking if this email is blacklisted
				if (not blacklisted($possibleEmail)) {
					addToList($possibleEmail);
					addConfidence($possibleEmail) if not($address =~ "(default, no info)");
				} else {
					print "this email is blacklisted: refused." if ($main::verbose>=5);
				}
				print "\n" if ($main::verbose>=5);
			}
		}
	}
}

# Low level function to add an email address to the list.
# Check if the address is allready prensent.
sub addToList {
	my $e = shift;
	my $found=0;
	$e =~ tr/A-Z/a-z/;

	foreach my $address (@main::abuseEmails) {
		if ($e eq @{$address}[0]) {
			$found=1;
			last;
		}
	}
	
	if ($found) {
		addConfidence($e); 
	} else {
		# Add to the list with 0 confidence
		push (@main::abuseEmails, [$e, 0]);
	}	
}

# Add confidence to a particular email address
sub addConfidence {
	my $e = shift;
	# Increment our confidence in $e
	foreach my $foo (@main::abuseEmails) {
		if (@{$foo}[0] eq $e) {
			++@{$foo}[1];
			last;
		}
	}	
}

# Get contact email addresses about $target from whois.
sub do_whois{ my ($server,  $target) = @_;
   my %secondary = ( 
		  "APNIC" => 'whois.apnic.net',
		  "RIPE" =>  'whois.ripe.net',
		  "KRNIC" => 'whois.krnic.net',
		  "JPNIC" => 'whois.nic.ad.jp',
		  "BRAZIL"  => 'whois.nic.br',
   );

   print "whois -h $server $target\n" if $main::showCommands;

   my $whois = eval { new XWhoisIP ( 
   		Server => $server,			Domain => $target,
   		Cache  => \$main::cachedir,	Expire => \$main::cacheexpire ) 
   };
   return unless $whois;

   my $netname = $whois->netname();
   my $maintainer = $whois->maintainer() if ($server eq "whois.arin.net");
   my $coord = $whois->contact_emails();
   my $coord_a = $whois->contact_emails_a() if (($server eq "whois.apnic.net") or ($server eq "whois.ripe.net"));

   # Recursing into this server.
   if( ! $whois->netname() ) {
      my @r = $whois->results();

      foreach my $r ( @r ) {
	  my( $name, $handle, $block) = split(/\t/, $r );
      
	   my $s;
	   if( ($s = block_size($block, $target)) < 0 ) {
	      print "Error: $target not in $block" if ($main::verbose>=2);
	   } else {
	      print "$block -- size $s\n" if ($main::verbose>=5);
	      do_whois($server, $handle);
	   }
     }
   }
   undef $whois;

   # Jumping into a secondary server.
   my $sub;
   if( (
   		(($sub = $maintainer) and $secondary{$sub}) or
   	   ((($sub) = $netname =~ /^(\w+)-/) and $secondary{$sub})
   	   ) and (
   	   	$secondary{$sub} ne $server	# Prevent infinite loops!
   	   )
    ) {
      print "$netname, jumping to $secondary{$sub}\n" if ($main::verbose>=5);
      return do_whois( $secondary{$sub}, $target );
   }

   # Merging collected data.
   $coord=$coord."\n".$coord_a if defined $coord_a;
   
   print "Coords found: \"$coord\"\n" if ($main::verbose>=4) and $coord;
   
   my @emails = split(/\n/, $coord);
   foreach my $em (@emails) {
   		if ($em =~ /([^\s]+\@[^\s]+)/) {
			AddEmailList($1);
 	  	}
   }
   
}


sub block_size {

   my ($block, $target ) = @_;
 
   my ($ip1, $ip2) = $block =~ /([0-9.]+)\s*-\s*([0-9.]+)/;
   my @ip1 = split(/\./, $ip1);
   my @ip2 = split(/\./, $ip2);
   my @t = split(/\./, $target);
   my $s = 0;;

   for( my $i=3; $i>=0; $i--) {
      if( (my $d = ($ip2[$i] - $ip1[$i] + 1)) != 1) {
	 if( $d == 256 ) { $s += 8; }
	 else {
	    my $b;
	    for($b = 0; $d > 1; $d /= 2) {$b++} 
	    $s += $b;
	 }
      }
      if ($t[$i] < $ip1[$i] and $t[$i] > $ip2[$i]) { return -1; }
   }
   return $s;
}

sub printUsage() {
    print << "EOU";
Usage: abuseEmail [options] ip

Options:
    --help          Prints this.

    --versbose=i    Set the verbose level to i. Current verbose levels are:
                    # 0: silent, only output the result
                    # 1: same as 0 but also output fatal errors (default)
                    # 2: same as 1 but also output non-fatal errors 
                    # 5: noisy: explain every action
					
    --useHostname   Specify if you want to use the hostname to guess some
    --noUseHostname adresses. Default: yes
	
    --useAbuseNet   Specify if you want to pass all the email addresses found
    --noUseAbuseNet into abuse.net whois directory. Default: yes
	
    --useDNSsoa     Specify if you want to dig  the subnet manager's email 
    --noUseDNSsoa   address using DNS SOA. Default: yes
	
    --useWhoisIP    Specify if you want to get some system managers's email
    --noUseWhoisIP  addresses using Whois on the IP address. Default: yes
	
    --showCommands  Show the Unix shell equivalent of every action taken (so 
                    the user can reproduce the technique).
	
    --batch         Output the result in an easy to parse way.

	--cache=<dir>   Make abuseEmail use this cache directory. Default: none
	--cacheexpire=i The number of seconds a cached entry should be used.
					N.B.: Outdated entries will not be deleted.

Examples:
    abuseEmail a.b.c.d
    abuseEmail --cache=/tmp/abuseEmailcache --verbose=5 --showCommands a.b.c.d
    abuseEmail --noUseHostname --noUseAbuseNet --verbose=2 a.b.c.d
    
    Here a.b.c.d must be replaced by a real IP address.
EOU
}

__END__

