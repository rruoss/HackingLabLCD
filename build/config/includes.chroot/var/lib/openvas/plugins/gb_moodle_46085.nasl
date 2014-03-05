###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_46085.nasl 13 2013-10-27 12:16:33Z jan $
#
# Moodle 'PHPCOVERAGE_HOME' Cross Site Scripting Vulnerability
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
tag_summary = "Moodle is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

Exploiting this vulnerability may allow an attacker to perform cross-
site scripting attacks on unsuspecting users in the context of the
affected website. As a result, the attacker may be able to steal cookie-
based authentication credentials and to launch other attacks.

Versions prior to Moodle 2.0.1 are vulnerable.";


if (description)
{
 script_id(103056);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
 script_bugtraq_id(46085);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Moodle 'PHPCOVERAGE_HOME' Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46085");
 script_xref(name : "URL" , value : "http://www.moodle.org");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if oodle is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_moodle_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Moodle/Version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"moodle"))exit(0);

url = string(dir,"/lib/spikephpcoverage/src/phpcoverage.remote.top.inc.php?PHPCOVERAGE_HOME=<script>alert(document.cookie)</script>"); 

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document.cookie\)</script>", check_header:TRUE, extra_check:make_list("ERROR: Could not locate PHPCOVERAGE_HOME"))) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
