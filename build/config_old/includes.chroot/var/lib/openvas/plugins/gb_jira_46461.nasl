###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jira_46461.nasl 13 2013-10-27 12:16:33Z jan $
#
# Atlassian JIRA Unspecified URI Redirection Vulnerability
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
tag_summary = "Atlassian JIRA is prone to a URI-redirection vulnerability because the
application fails to properly sanitize user-supplied input.

A successful exploit may aid in phishing attacks; other attacks are
also possible.

Versions prior to Atlassian JIRA 4.2.2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103085);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
 script_bugtraq_id(46461);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Atlassian JIRA Unspecified URI Redirection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46461");
 script_xref(name : "URL" , value : "http://www.atlassian.com/software/jira/");
 script_xref(name : "URL" , value : "http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2011-02-21");

 script_description(desc);
 script_summary("Determine if installed Atlassian JIRA is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_atlassian_jira_detect.nasl");
 script_require_ports("Services/www", 80);
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

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"Atlassian_JIRA")) {

  if(version_is_less(version: vers, test_version: "4.2.2")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
