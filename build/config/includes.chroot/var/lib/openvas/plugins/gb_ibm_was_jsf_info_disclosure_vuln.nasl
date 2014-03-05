###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_jsf_info_disclosure_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability
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
tag_impact = "Successful exploitation will let remote unauthorized attackers to access
  or view files or obtain sensitive information.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 8.x before 8.0.0.1";
tag_insight = "The flaw is caused by improper handling of requests in 'JSF' applications.
  A remote attacker could gain unauthorized access to view files on the host.";
tag_solution = "Apply the latest Fix Pack (8.0.0.1 or later) or APAR PM45992
  http://www-01.ibm.com/support/docview.wss?uid=swg21474220";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(801998);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-1368");
  script_bugtraq_id(50463);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-03 18:00:39 +0530 (Thu, 03 Nov 2011)");
  script_name("IBM WebSphere Application Server JSF Application Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70168");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM45992");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg24030916");

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

## Check for IBM WebSphere Application Server versions
if(version_is_equal(version: vers, test_version: "8.0.0.0")){
  security_warning(port:port);
}
