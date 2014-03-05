###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpgraphy_47634.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpGraphy 'theme_dir' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "phpGraphy is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

phpGraphy 0.9.13b is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103154);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
 script_bugtraq_id(47634);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpGraphy 'theme_dir' Parameter Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47634");
 script_xref(name : "URL" , value : "http://phpgraphy.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517722");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if phpGraphy is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/phpgraphy",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/themes/default/header.inc.php?theme_dir=%22%3E%3Cscript%3Ealert%28/openvas-xss-test/%29;%3C/script%3E"); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\);</script>",check_header:TRUE,extra_check:"phpgraphy.css")) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
