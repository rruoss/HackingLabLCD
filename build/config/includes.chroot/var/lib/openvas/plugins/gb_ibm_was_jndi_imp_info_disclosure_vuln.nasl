###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_jndi_imp_info_disclosure_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server JNDI information disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "For WebSphere Application Server 6.0:
  Apply the latest Fix Pack (6.0.2.39 or later) or APAR PK91414

  For WebSphere Application Server 6.1:
  Apply the latest Fix Pack (6.1.0.29 or later) or APAR PK91414

  For WebSphere Application Server 7.1:
  Apply the latest Fix Pack (7.0.0.7 or later) or APAR PK91414

  For updates refer to http://www.ibm.com/support/docview.wss?uid=swg1PK91414";

tag_impact = "Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) 6.0 before 6.0.2.39,
  6.1 before 6.1.0.29, and 7.0 before 7.0.0.7";
tag_insight = "The flaw is due to error in the Naming and Directory Interface (JNDI)
  implementation. It does not properly restrict access to UserRegistry object
  methods, which allows remote attackers to obtain sensitive information via a
  crafted method call.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(802400);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2009-2747");
  script_bugtraq_id(37355);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-04 15:09:13 +0530 (Fri, 04 Nov 2011)");
  script_name("IBM WebSphere Application Server JNDI information disclosure Vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54228");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg1PK99480");
  script_xref(name : "URL" , value : "http://www.ibm.com/support/docview.wss?uid=swg1PK91414");

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
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

## Check for IBM WebSphere Application Server versions
if(version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.6") ||
   version_in_range(version: vers, test_version: "6.0", test_version2: "6.0.2.38") ||
   version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.28")) {
  security_warning(port:port);
}
