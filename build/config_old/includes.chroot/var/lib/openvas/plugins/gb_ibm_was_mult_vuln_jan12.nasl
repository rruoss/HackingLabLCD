###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_mult_vuln_jan12.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - (Jan2012)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to conduct cross-site scripting
  attacks or to obtain sensitive information and cause a denial of service.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.41";
tag_insight = "The flaws are due to
  - An unspecified error exists in a WS-Security policy enabled Java API for
    XML Web Services (JAX-WS) application.
  - A Certain unspecified input passed to the web messaging component is not
    properly sanitised before being returned to the user.
  - A SibRaRecoverableSiXaResource class in the Default Messaging Component,
    does not properly handle a Service Integration Bus (SIB) dump operation
    involving the First Failure Data Capture (FFDC) introspection code.";
tag_solution = "Upgrade to version 6.1.0.41 or later,
  For updates refer to  http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802412);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5066", "CVE-2011-5065", "CVE-2011-1377");
  script_bugtraq_id(51560, 51559, 50310);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-18 17:27:41 +0530 (Wed, 18 Jan 2012)");
  script_name("IBM WebSphere Application Server (WAS) Multiple Vulnerabilities - (Jan2012)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46469");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72299");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27011716");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM50205");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Check for IBM WebSphere Application Server versions 6.1 before 6.1.0.41
if(version_in_range(version: vers, test_version: "6.1", test_version2:"6.1.0.40")){
  security_hole(port:port);
}
