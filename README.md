ossec-email-abuse
=================

An active response script for OSSEC that sends an email to the abuse contact of the offending IPs.

Requirements:
* host,dig,whois,mailx *nix programs
* Perl Net::DNS CPAN module

Installation:
-------------
1. Download the two scripts
<pre>
su root
cd /var/ossec/active-response/bin
wget abuseEmail.pl
wget email-abuse.sh
chmod 500 abuseEmail.pl
chmod 500 email-abuse.sh
chown root.ossec abuseEmail.pl
chown root.ossec email-abuse.sh
</pre>
2. Test that abuseEmail.pl is working
<pre>
./abuseEmail-1.1.3.pl 207.97.209.147
</pre>
The return should be "abuse@rackspace.com     1"
If you get any errors, load up any libraries that are missing.

3. Edit email-abuse.sh and change 
<pre>
### CHANGE THESE VARIABLES TO YOUR SETUP
EFROM="abuse@mydomain.com"
ESUBJECT="Unauthorized access attempt from $IP"
ENAME="Your Name"
EDOMAIN="mydomain.com"
ECONTACT="myemail@mydomain.com"
###
</pre>
4. Edit /var/ossec/etc/ossec.conf and add
`````xml
<command>
    <name>email-abuse</name>
    <executable>email-abuse.sh</executable>
    <timeout_allowed>no</timeout_allowed>
    <expect>srcip</expect>
</command>

  <active-response>
    <!-- send an email to the abuse contact of the
       - offendingIP
      -->
    <command>email-abuse</command>
    <location>local</location>
    <level>6</level>
  </active-response>
`````
