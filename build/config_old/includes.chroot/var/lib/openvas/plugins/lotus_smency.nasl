# OpenVAS Vulnerability Test
# $Id: lotus_smency.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ScanMail file check
#
# Authors:
# DokFLeed <dokfleed at dokfleed.net>
#
# Copyright:
# Copyright (C) 2004 by DokFLeed
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
tag_solution = "Password protect access to these files.";

tag_summary = "This script attempts to read sensitive files used by Trend
ScanMail, an anti-virus protection program for Domino (formerly Lotus Notes).
An attacker, exploiting this flaw, may gain access to confidential data or
disable the anti-virus protection.";

# Looking for smency.nsf Trend/Lotus

if(description)
{
   script_id(14312);
   script_version("$Revision: 17 $");
   script_tag(name:"cvss_base", value:"5.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
   script_tag(name:"risk_factor", value:"Medium");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_bugtraq_id(11612);
   script_name("ScanMail file check"); 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;

   script_description(desc);
   script_summary("Checks for the presence ScanMail files"); 
   script_category(ACT_GATHER_INFO); 
   script_family("Web application abuses"); 
   script_copyright("This script is Copyright (C) 2004 by DokFLeed"); 
   script_dependencies("find_service.nasl", "http_version.nasl");
   script_require_ports("Services/www", 80);
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "summary" , value : tag_summary);
     script_tag(name : "solution" , value : tag_solution);
   }
   exit(0); 
}

# Start of Code  
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);


files = make_array("/smency.nsf"   , "Encyclopedia",
                   "/smconf.nsf"   , "Configuration",
                   "/smhelp.nsf"   , "Help",
                   "/smftypes.nsf" , "File Types",
                   "/smmsg.nsf"    , "Messages",
                   "/smquar.nsf"   , "Quarantine",
                   "/smtime.nsf"   , "Scheduler",
                   "/smsmvlog.nsf" , "Log",
                   "/smadmr5.nsf"  , "Admin Add-in");
report = "";
foreach path (keys(files))
{
  req = http_get(item:path, port:port);
  r = http_keepalive_send_recv(port:port, data:req);

  if (r == NULL) exit(0);

  if ("Trend ScanMail" >< r)
  {
    if (!report)
    {
      report =
"Sensitive files used by Trend ScanMail, an anti-virus protection
program for Domino (formerly Lotus Notes), are readable via the web.
These files might expose confidential data or allow an attacker to
disable the anti-virus protection.

   Solution:
   " + tag_solution + "

The following files were found:
";
    }
    report += string("\n    ", path, " - ", files[path]);
  }
}
if (report) security_warning(port:port, data:report);