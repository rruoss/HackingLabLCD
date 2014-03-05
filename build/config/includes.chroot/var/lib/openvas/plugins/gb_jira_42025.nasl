###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jira_42025.nasl 14 2013-10-27 12:33:37Z jan $
#
# Jira Cross Site Scripting and Information Disclosure Vulnerabilities
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
tag_summary = "Jira is prone to multiple cross-site scripting vulnerabilities and an
information disclosure vulnerability because the application fails to
sufficiently sanitize user-supplied input.

Attackers can exploit these issues to obtain sensitive information,
steal cookie-based authentication information, and execute arbitrary
client-side scripts in the context of the browser.

Jira 4.01 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100740);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-03 13:36:27 +0200 (Tue, 03 Aug 2010)");
 script_bugtraq_id(42025);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Jira Cross Site Scripting and Information Disclosure Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42025");
 script_xref(name : "URL" , value : "http://www.atlassian.com/software/jira/");

 script_description(desc);
 script_summary("Determine if installed jira version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_atlassian_jira_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

jiraPort = get_http_port(default:8080);
if(!jiraPort){
  exit(0);
}

jiraVer = get_kb_item("www/" + jiraPort + "/Atlassian_JIRA");
if(!jiraVer){
  exit(0);
}

if("#" >< jiraVer) {
  jver = split(jiraVer,sep:"#",keep:FALSE);
  if(!isnull(jver[0])) {
    jiraVer = jver[0];
  }
} 

if(jiraVer != NULL) {
  if(version_is_equal(version:jiraVer, test_version:"4.0.1")) {
   security_warning(port:jiraPort);
   exit(0);
  }
}

exit(0);
