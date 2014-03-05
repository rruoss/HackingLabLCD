# OpenVAS Vulnerability Test
# $Id: cgiwrap.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cobalt RaQ2 cgiwrap
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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
tag_summary = "'cgiwrap' is installed. If you are running an unpatched Cobalt RaQ, 
the version of cgiwrap distributed with that system has a known
security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

This flaw exists only on the Cobalt modified cgiwrap. Standard builds
of cgiwrap are not affected.";

tag_solution = "upgrade your Cobalt RaQ to apply fix";

if(description)
{
 script_id(10041);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1238, 777);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-1999-1530", "CVE-2000-0431");


 name = "Cobalt RaQ2 cgiwrap";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);

 summary = "Checks for the presence of /cgi-bin/cgiwrap";
   
 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}	  
  
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"cgiwrap", port:port);
if(res)security_hole(port);

   
