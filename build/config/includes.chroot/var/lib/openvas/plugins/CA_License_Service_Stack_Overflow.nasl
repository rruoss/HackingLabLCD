# OpenVAS Vulnerability Test
# $Id: CA_License_Service_Stack_Overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CA License Service Multiple Vulnerabilities
#
# Authors:
# KK Liu
# Modifications by Tenable Network Security:
#  - Fixed the request
#  - Shorter description
#  - Fixed the version number check 
#  - Added a check on port 10202, 10203
#
# Copyright:
# Copyright (C) 2005 KK Liu
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
tag_summary = "Arbitrary code can be executed on the remote host.

Description :

The remote host is running the Computer Associate License Application.

The remote version of this software is vulnerable to several flaws which
may allow a remote attacker to execute arbitrary code on the remote host
with the SYSTEM privileges.";

tag_solution = "http://supportconnectw.ca.com/public/ca_common_docs/security_notice.asp";

if(description)
{
 script_id(17307);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12705);
 script_cve_id("CVE-2005-0581", "CVE-2005-0582", "CVE-2005-0583");

 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "CA License Service Multiple Vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "CA License Service Stack Overflow";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 KK Liu");
 script_family( "Gain a shell remotely");
 script_require_ports(10202, 10203, 10204);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.eeye.com/html/research/advisories/AD20050302.html");
 exit(0);
}

include('misc_func.inc');

req = 'A0 GETCONFIG SELF 0 <EOM>\r\n';
ports = make_list(10202, 10203, 10204);
foreach port ( ports )
{
 if ( get_port_state(port) ) 
  {
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:620);
	close(soc);
	if ( strlen(r) > 0 )
	{
     	chkstr = strstr(r, "VERSION<");
	if (chkstr ) 
 	{
	 register_service(port:port, proto:"CA_License_Service");
         if (egrep (pattern:"VERSION<[0-9] 1\.(5[3-9].*|60.*|61(\.[0-8])?)>", string:chkstr)) 
	 {
          security_hole(port);
	 }
	}
       } 
    }
  }
}
