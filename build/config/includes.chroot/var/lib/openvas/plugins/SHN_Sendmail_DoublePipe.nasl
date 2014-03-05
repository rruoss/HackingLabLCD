# OpenVAS Vulnerability Test
# $Id: SHN_Sendmail_DoublePipe.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sendmail 8.8.8 to 8.12.7 Double Pipe Access Validation Vulnerability
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
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
tag_summary = "smrsh (supplied by Sendmail) is designed to prevent the execution of
commands outside of the restricted environment. However, when commands
are entered using either double pipes or a mixture of dot
and slash characters, a user may be able to bypass the checks
performed by smrsh. This can lead to the execution of commands
outside of the restricted environment.";

tag_solution = "upgrade to the latest version of Sendmail (or at least 8.12.8).";

if(description)
{
 script_id(11321);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5845);
 script_cve_id("CVE-2002-1165", "CVE-2002-1337");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_xref(name:"RHSA", value:"RHSA-2003:073-06");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:023");

 
 name = "Sendmail 8.8.8 to 8.12.7 Double Pipe Access Validation Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks sendmail's version number"; 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
 
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
 if(egrep(pattern:"Sendmail.*(8\.8\.[89]|8\.9\..*|8\.1[01]\.*|8\.12\.[0-7][^0-9])/", string:banner))
        security_hole(port);
}

