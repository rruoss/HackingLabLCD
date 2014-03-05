###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln_mar11.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - March 2011
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let attackers to execute arbitrary script code,
  steal cookie-based authentication credentials, obtain sensitive information,
  and perform unauthorized actions.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions prior to 7.0.0.15.";
tag_insight = "- An error in the installer that creates a temporary directory for logs with
    insecure permissions.
  - An input validation error in the IVT application, which could allow cross
    site scripting attacks.
  - An error related to trace requests handling in the plug-in component.
  - The Security component when a J2EE 1.4 application is used, determines the
    security role mapping on the basis of the ibm-application-bnd.xml file
    instead of the intended ibm-application-bnd.xmi file allows remote
    authenticated users to gain privileges.
  - The Service Integration Bus (SIB) messaging engine allows remote attackers
    to cause a denial of service by performing close operations via network
    connections to a queue manager.
  - Memory leak in the messaging engine allows remote attackers to cause a
    denial of service via network connections associated with a NULL return
    value from a synchronous JMS receive call.
  - The Session Initiation Protocol (SIP) Proxy in the HTTP Transport component
    allows remote attackers to cause a denial of service by sending many UDP
    messages.
  - Memory leak in org.apache.jasper.runtime.JspWriterImpl.response in the
    JavaServer Pages (JSP) component allows remote attackers to cause a denial
    of service by accessing a JSP page of an application that is repeatedly
    stopped and restarted.";
tag_solution = "Upgrade to IBM WebSphere Application Server version 7.0.0.15 or later,
  http://www-01.ibm.com/support/docview.wss?uid=swg24028875";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801861);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1307", "CVE-2011-1308", "CVE-2011-1309",
                "CVE-2011-1311", "CVE-2011-1314", "CVE-2011-1315",
                "CVE-2011-1316", "CVE-2011-1318");
  script_bugtraq_id(46736);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - March 2011");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0564");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Get Version from KB
vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

## Check for IBM WebSphere Application Server versions prior to 7.0.0.15
if(version_is_less(version: vers, test_version: "7.0.0.15")){
  security_hole(port:port);
}
