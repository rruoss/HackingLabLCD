###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_confluence_47398.nasl 13 2013-10-27 12:16:33Z jan $
#
# Atlassian Confluence Multiple Cross Site Scripting Vulnerabilities
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
tag_summary = "Atlassian Confluence is prone to multiple cross-site scripting
vulnerabilities because it fails to sufficiently sanitize user-
supplied data.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

The following versions are vulnerable:

Atlassian Confluence versions 2.7 through 3.4.5 Atlassian Confluence
versions 2.9 through 3.4.8";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103153";
CPE = "cpe:/a:atlassian:confluence";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
 script_bugtraq_id(47398);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Atlassian Confluence Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47398");
 script_xref(name : "URL" , value : "http://jira.atlassian.com/browse/CONF-21508");
 script_xref(name : "URL" , value : "http://jira.atlassian.com/browse/CONF-21819");
 script_xref(name : "URL" , value : "http://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2011-01-18");
 script_xref(name : "URL" , value : "http://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2011-03-24");
 script_xref(name : "URL" , value : "http://www.atlassian.com/software/confluence/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Atlassian Confluence version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_atlassian_confluence_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("atlassian_confluence/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if (report_paranoia < 2) exit(0);

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {
  if(version_is_less(version: vers, test_version: "3.4.6") ||
     version_in_range(version: vers,test_version: "3.4.7",test_version2: "3.4.8")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
