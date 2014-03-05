###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_TextPattern_43055.nasl 14 2013-10-27 12:33:37Z jan $
#
# TextPattern 'txplib_db.php' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "TextPattern is prone to a cross-site scripting vulnerability because
it fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

TextPattern 4.2.0 is vulnerable; others versions may also be affected.";


if (description)
{
 script_id(100793);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-09 16:30:22 +0200 (Thu, 09 Sep 2010)");
 script_bugtraq_id(43055);

 script_name("TextPattern 'txplib_db.php' Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43055");
 script_xref(name : "URL" , value : "http://www.textpattern.com/");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4963.php");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if TextPattern is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,"/cms/index.php?q=%3Cscript%3Ealert(0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374)%3C/script%3E"); 

  if(http_vuln_check(port:port,
		     url:url,
		     check_header: TRUE,
		     pattern:"<script>alert\(0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374\)</script>",
		     extra_check:"Textpattern Warning")) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
