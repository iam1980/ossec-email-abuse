#!/bin/sh
# Tries to find the abuse contact of the offending IP and emails the attack log
# copy at /var/ossec/active-response/bin/email-abuse.sh
# Requirements: * abuseEmail-1.1.3.pl (https://gist.github.com/4641962)
#               * Perl Net::DNS CPAN module
#  	* host,dig,whois (CENT OS: yum install bind-utils jwhois)
# Author: Iraklis Mathiopoulos <mathiopoulos@gmail.com>
# Last modified: Jan 26, 2013

IP=$3
ALERTID=$4
RULEID=$5

### CHANGE THESE VARIABLES TO YOUR SETUP
EFROM="root@santorinibookings.gr"
ESUBJECT="Unauthorized access attempt from $IP"
ENAME="Iraklis Mathiopoulos"
EDOMAIN="santorinibookings.gr"
ECONTACT="mathiopoulosc@gmail.com"
###

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`

# Trying to find the abuse email
ABUSEEMAILS=($(bin/abuseEmail-1.1.3.pl $IP --verbose=0))

ABUSEFOUND=false
ABUSEEMAIL=""
ABUSEEMAILCC=""
for i in "${ABUSEEMAILS[@]}"
do
        case $i in
                ''|*[!0-9]*)
                        ABUSEFOUND=true
                        if [ -z "$ABUSEEMAIL" ]; then
                                ABUSEEMAIL=$i
                        else
                                ABUSEEMAILCC=${ABUSEEMAILCC}${i},
                        fi
                ;;
                *) ;;
        esac

done
if $ABUSEFOUND ; then
	ABUSEEMAILCC=${ABUSEEMAILCC%?}
else
	echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8 Could not find an abuse email for $IP" >> ${PWD}/../logs/active-responses.log
	exit 0
fi

# Logging the call
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8 Sending email for $IP to $ABUSEEMAIL" >> ${PWD}/../logs/active-responses.log

# Getting alert time
ALERTTIME=`echo "$ALERTID" | cut -d  "." -f 1`

# Getting end of alert
ALERTLAST=`echo "$ALERTID" | cut -d  "." -f 2`

# Setting up the email body
EBODY="To whom it may concern:

It appears that $IP is trying to break in and is triggering my IDS. I have included a 
snippet from the log files in question below in plain text format. I would appreciate 
any help you could give me in stopping the source of these access attempts on my system. 

Please contact me at $ECONTACT if I can be of assistance.

Best Regards,
$ENAME
$EDOMAIN admin

---[BEGIN OF LOG]---
"

# Getting relevant alerts
LOG=$(grep -A 10 "$ALERTTIME" ${PWD}/../logs/alerts/alerts.log | grep -v ".$ALERTLAST: " -A 10)

# Appending the log to the body of the email
EBODYLOG=${EBODY}${LOG}
EBODYLOG=${EBODYLOG}"\n---[END OF LOG]---"

# send the email
echo -e "$EBODYLOG" | /bin/mailx -r "$EFROM" -s "$ESUBJECT" -c "$ABUSEEMAILCC" "$ABUSEEMAIL"
