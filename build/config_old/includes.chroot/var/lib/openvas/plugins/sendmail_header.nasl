# OpenVAS Vulnerability Test
# $Id: sendmail_header.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sendmail remote header buffer overflow
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2003 SECNAP Network Security
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
tag_summary = "The remote sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.7 are vulnerable.";

tag_solution = "Upgrade to Sendmail ver 8.12.8 or greater or
if you cannot upgrade, apply patches for 8.10-12 here:

http://www.sendmail.org/patchcr.html

NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of sendmail
may still falsely show vulnerability.

*** OpenVAS reports this vulnerability using only
*** the banner of the remote SMTP server. Therefore,
*** this might be a false positive.

see http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?oid=21950
    http://www.cert.org/advisories/CA-2003-07.html
    http://www.kb.cert.org/vuls/id/398025";


if(description)
{
 script_id(11316);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2794, 6991);
 script_cve_id("CVE-2001-1349", "CVE-2002-1337");
 script_xref(name:"IAVA", value:"2003-A-0002");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "Sendmail remote header buffer overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
	
 script_description(desc);
 
 summary = "Checks the version number"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 SECNAP Network Security");
 
 family = "SMTP problems";
 script_family(family);
 script_dependencies("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
  # Digital Defense came up with this nice regex :
  if(egrep(pattern:".*Sendmail.*(Switch\-((1\.)|(2\.(0\.|1\.[0-4])))|(\/|UCB| )([5-7]\.|8\.([0-9](\.|;|$)|10\.|11\.[0-6]|12\.[0-7](\/| |\.|\+)))).*", string:banner, icase:TRUE))
		security_hole(port);

  # Since the regex above is VERY complicated, I also include this simpler one, in case the first misses
  # something.
  else if(egrep(pattern:".*Sendmail (5\.79.*|5\.[89].*|[67]\..*|8\.[0-9]\..*|8\.10\..*|8\.11\.[0-6]|8\.12\.[0-7]|SMI-8\.([0-9]|1[0-2]))/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
