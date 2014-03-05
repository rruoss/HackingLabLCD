# OpenVAS Vulnerability Test
# $Id: snmp_default_communities.nasl 77 2013-11-25 13:45:17Z mime $
# Description: Default community names of the SNMP Agent
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications :
# 	02/22/2000, Renaud Deraison : added more communities
#	06/08/2000, Renaud Deraison : fixed a problem in the packets sent
#       24/02/2002, Richard Lush    : Modified to find the error code
#	08/03/2002, Axel Nennker    : cisco ILMI solution
#	23/05/2002, Axel Nennker    : ONE report for this plugin
#                   some stupid HP Printers answer to every community
#       20/04/2005, Javier Fernandez-Sanguino, added more communities for
#                   Cisco's aironet
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_impact = "If an attacker is able to guess a PUBLIC community string, they would be able to
read SNMP data (depending on which MIBs are installed) from the remote device.
This information might include system time, IP addresses, interfaces, processes
running, etc.

If an attacker is able to guess a PRIVATE community string (WRITE or 'writeall'
access), they will have the ability to change information on the remote machine.
This could be a huge security hole, enabling remote attackers to wreak complete
havoc such as routing network traffic, initiating processes, etc.  In essence,
'writeall' access will give the remote attacker full administrative rights over
the remote machine.

Note that this test only gathers information and does not attempt to write to
the remote device.  Thus it is not possible to determine automatically whether
the reported community is public or private.

Also note that information made available through a guessable community string
might or might not contain sensitive data.  Please review the information
available through the reported community string to determine the impact of this
disclosure.

Recommendations:
Determine if the detected community string is a private community string.
Determine whether a public community string exposes sensitive information.
Disable the SNMP service if you don't use it or change the default community string.";

tag_summary = "Simple Network Management Protocol (SNMP) is a protocol
which can be used by administrators to remotely manage a computer or network
device.  There are typically 2 modes of remote SNMP monitoring.  These modes
are roughly 'READ' and 'WRITE' (or PUBLIC and PRIVATE).";


# References:
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998 
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
# 
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware 
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# 
# http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
# http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15 

desc = "
 Summary:
 " + tag_summary + "
 Impact:
 " + tag_impact;

if(description)
{
 script_id(10264);
 script_version("$Revision: 77 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-25 14:45:17 +0100 (Mon, 25 Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_xref(name:"IAVA", value:"2001-B-0001");
 script_cve_id("CVE-1999-0516");
 script_name("Default community names of the SNMP Agent");
 
 script_description(desc);

 script_summary("Default community names of the SNMP Agent");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 script_family("SNMP");
 script_dependencies("snmp_detect.nasl");
 script_require_udp_ports("Services/snmp", 161);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "impact" , value : tag_impact);
 }

 exit(0);
}


#
# The script code starts here
#

include('global_settings.inc');

def = get_kb_item("SNMP/community");
if(def)loggued = 1;
loggued = 0;

port = get_kb_item("Services/snmp");
if(!port)port = 161;

if(get_udp_port_state(port))
 {

i = 0;
comm[i++]= "private";
comm[i++]= "public";
comm[i++]= "secret"; 		# for Cisco equipment
comm[i++]= "cisco"; 		# for Cisco equipment
comm[i++]= "write";
comm[i++]= "test";
comm[i++]= "guest";
comm[i++]= "ilmi";
comm[i++]= "ILMI";
comm[i++]= "system";
comm[i++]= "all";
comm[i++]= "admin";
comm[i++]= "all private";  	# Solaris 2.5.1 and 2.6
comm[i++]= "password";
if ( thorough_tests )
{
 comm[i++]= "monitor";
 comm[i++]= "agent";
 comm[i++]= "manager";
 comm[i++]= "OrigEquipMfr";      # Brocade
 comm[i++]= "default";
 comm[i++]= "tivoli";
 comm[i++]= "openview";
 comm[i++]= "community";
 comm[i++]= "snmp";
 comm[i++]= "snmpd"; 		# HP Snmp agent
 comm[i++]= "Secret C0de";	# Brocade
 comm[i++]= "security";
 comm[i++]= "rmon";
 comm[i++]= "rmon_admin";
 comm[i++]= "hp_admin";
 comm[i++]= "NoGaH$@!"; # Avaya
 comm[i++]= "0392a0";
# See http://online.securityfocus.com/bid/3758/discussion/
 comm[i++] = "xyzzy";
 comm[i++] = "agent_steal";
 comm[i++] = "freekevin";
 comm[i++] = "fubar";

# see http://www.cirt.net/cgi-bin/passwd.pl
 comm[i++] = "apc"; 		# for APC Web/SNMP Management Card AP9606
 comm[i++] = "ANYCOM"; 		# for 3COM NetBuilder
 comm[i++] = "cable-docsis";	# for Cisco equipment
 comm[i++] = "c"; 		# for Cisco equipment
 comm[i++] = "cc"; 		# for Cisco equipment
 comm[i++] = "Cisco router"; 	# for Cisco equipment
 comm[i++] = "cascade"; 		# for Lucent equipment
 comm[i++] = "comcomcom"; 	# for 3COM AirConnect AP

 # HP JetDirect equipement
 comm[i++] = "internal";
 comm[i++] = "blue";
 comm[i++] = "yellow";

 comm[i++] = "TENmanUFactOryPOWER";

 # Cisco Aironet
 # see http://www.cisco.com/en/US/products/hw/wireless/ps458/products_configuration_guide_chapter09186a008007f7c6.html#xtocid708110
 comm[i++] = "proxy";
 comm[i++] = "regional";
 comm[i++] = "core";

# Add router name
name = get_host_name();
if (name !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
{
  # We have a name, not an IP
  names[0] = name;
  dot = strstr(name, '.');
  if (dot)
  {
    name = name - dot;	# Use short name
    names[1] = name;
  }
  foreach n (names)
  {
   j = max_index(comm);
   for (i = 0; i < j && n != comm[i]; i ++)
     ;
   if (i < j) comm[j] = n;	# The name is not already in the list
  }
 }
}


report="";
count=0;

for (i = 0; comm[i]; i = i + 1)
{
	srcaddr = this_host();
	dstaddr = get_host_ip();
	community = comm[i];
	
	SNMP_BASE = 31;
	COMMUNITY_SIZE = strlen(community);
	
	sz = COMMUNITY_SIZE % 256;
	

	len = SNMP_BASE + COMMUNITY_SIZE;
	len_hi = len / 256;
	len_lo = len % 256;
	sendata = raw_string(
		0x30, 0x82, len_hi, len_lo, 
		0x02, 0x01, 0x00, 0x04,
		sz);
		
		
	sendata = sendata + community +
		raw_string( 0xA1, 
		0x18, 0x02, 0x01, 0x01, 
		0x02, 0x01, 0x00, 0x02, 
		0x01, 0x00, 0x30, 0x0D, 
		0x30, 0x82, 0x00, 0x09, 
		0x06, 0x05, 0x2B, 0x06, 
		0x01, 0x02, 0x01, 0x05, 
		0x00); 

	
	dstport = port;
	soc[i] = open_sock_udp(dstport);
	send(socket:soc[i], data:sendata);
	usleep(10000); # Cisco don't like to receive too many packets
		       # at the same time
}


for(j=0; comm[j] ; j = j + 1)
{
 result = recv(socket:soc[j], length:200, timeout:1);
 close(soc[j]);
 
 
	if (strlen(result)>0)
	{
	  if(comm[j] >< result)
	  {
	   off = 0;
	   sl = strlen(comm[j]);
          
           # Find the offset required to obtain the Error Code
           for(offset=0; offset<10; offset=offset+1)
           {
            if((ord(result[9+sl+offset]) == 0x02))
            {
		off=offset;
		offset=10;
	    }
           }

           sl=sl+off;
           noerror=1;
           rep_port = NULL;

	   # Check the SNMP Error Status Type/Len/Value
           # Anything other than 0x00 is an error code
	   if(!(ord(result[12+sl]) == 0x02))noerror = 0;
           if(!(ord(result[13+sl]) == 0x01))noerror = 0;
           if(!(ord(result[14+sl]) == 0x00))noerror = 0;

	   if(noerror)
	   {
            count = count + 1;
	    hole_data = string("SNMP Agent responded as expected with community name: ", comm[j]);
            if (comm[j] == "ILMI") {
	     hole_data = string( hole_data, " If the target is a Cisco Product, please read http://www.cisco.com/warp/public/707/ios-snmp-ilmi-vuln-pub.shtml" );
            }
            report = report + string("\n") + hole_data;
	    if(!loggued){
	  	set_kb_item(name:"SNMP/community", value:comm[j]);
		set_kb_item(name:"SNMP/port", value:port);
		loggued = 1;
		}
	    }
	   }
	  }
	}
}


if (count > 4) {
 report = string("The device answered to more than 4 community strings.\n",
  	         "This may be a false positive or a community-less SNMP server\n",
		 "HP printers answer to all community strings.\n",
		 report);
}
  if (strlen(report) > 0) {

    report = desc + '\n' + report + '\n';

    security_hole(port:port, data:report, protocol:"udp");
  }
