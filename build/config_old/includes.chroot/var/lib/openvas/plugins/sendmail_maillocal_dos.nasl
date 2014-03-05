# OpenVAS Vulnerability Test
# $Id: sendmail_maillocal_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sendmail mail.local DOS
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
tag_summary = "mail.local in the remote sendmail server, according to its 
version number, does not properly identify the .\n string 
which identifies the end of message text, which allows a 
remote attacker to cause a denial of service or corrupt 
mailboxes via a message line that is 2047 characters 
long and ends in .\n.";

tag_solution = "Install sendmail version 8.10.0 and higher, or install
a vendor supplied patch.";

if(description)
{
 script_id(11351);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1146);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-0319");

 name = "Sendmail mail.local DOS";
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

 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");

 family = "SMTP problems";
 script_family(family);
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
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
 #looking for Sendmail 5.58,5,59, 8.6.*, 8.7.*, 8.8.*, 8.9.1, 8.9.3(icat.nist.gov)
 #bugtrap id 1146 only said 8.9.3, I guess it want to say 8.9.3 and older
 if(egrep(pattern:".*sendmail[^0-9]*(5\.5[89]|8\.([6-8]|[6-8]\.[0-9]+)|8\.9\.[1-3]|SMI-[0-8]\.)/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
