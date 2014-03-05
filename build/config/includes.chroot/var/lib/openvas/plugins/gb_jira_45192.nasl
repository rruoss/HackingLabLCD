###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jira_45192.nasl 14 2013-10-27 12:33:37Z jan $
#
# Atlassian JIRA Multiple Cross Site Scripting Vulnerabilities
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
tag_summary = "Atlassian JIRA is prone to multiple cross-site scripting
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary HTML and
script code in the browser of an unsuspecting user in the context of
the affected site. This may let the attacker steal cookie-based
authentication credentials and launch other attacks.

Versions prior to Atlassian JIRA 4.2.1 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(100936);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-12-06 15:55:47 +0100 (Mon, 06 Dec 2010)");
 script_bugtraq_id(45192);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Atlassian JIRA Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45192");
 script_xref(name : "URL" , value : "http://www.atlassian.com/software/jira/");
 script_xref(name : "URL" , value : "http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2010-12-06#JIRASecurityAdvisory2010-12-06-xssfix");

 script_description(desc);
 script_summary("Determine if installed Atlassian JIRA version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_atlassian_jira_detect.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"Atlassian_JIRA")) {

  if("#" >< vers) {
    jver = split(vers,sep:"#",keep:FALSE);
    if(!isnull(jver[0])) {
      vers = jver[0];
    }
  }  

  if(version_is_less(version: vers, test_version: "4.2.1")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
