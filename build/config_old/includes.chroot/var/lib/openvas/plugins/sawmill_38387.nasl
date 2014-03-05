###############################################################################
# OpenVAS Vulnerability Test
# $Id: sawmill_38387.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sawmill Unspecified Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-29
# Updated the CVE
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
tag_summary = "Sawmill is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

This issue affects versions prior to 7.2.18.";

tag_solution = "An update is available. Please see the references for details.";

if (description)
{
 script_id(100507);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)");
 script_bugtraq_id(38387);
 script_cve_id("CVE-2010-1079");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Sawmill Unspecified Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38387");
 script_xref(name : "URL" , value : "http://www.sawmill.net");
 script_xref(name : "URL" , value : "http://www.sawmill.net/version_history7.html");

 script_description(desc);
 script_summary("Determine if Sawmill version is < 7.2.18");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8987);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8987);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: Sawmill/" >!< banner)exit(0);

version = eregmatch(pattern: "Server: Sawmill/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "7.2.18")) {
  security_warning(port:port);
  exit(0);
}

exit(0);

