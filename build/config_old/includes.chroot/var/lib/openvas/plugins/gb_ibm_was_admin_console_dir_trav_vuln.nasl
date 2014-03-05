###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_admin_console_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server Administration Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to read arbitrary files on the
  affected application and obtain sensitive information that may lead to
  further attacks.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1 before 6.1.0.41,
  7.0 before 7.0.0.19 and 8.0 before 8.0.0.1";
tag_insight = "The flaw is due to error in administration console which fails to
  handle certain requests. This allows remote attackers to read arbitrary
  files via a '../' (dot dot) in the URI.";
tag_solution = "Upgrade IBM WebSphere Application Server to 6.1.0.41 or 7.0.0.19 or
  8.0.0.1
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg24028875";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to directory traversal vulnerability.";

if(description)
{
  script_id(801977);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-1359");
  script_bugtraq_id(49362);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM WebSphere Application Server Administration Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/74817");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45749");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69473");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21509257");

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
if(version_is_equal(version: vers, test_version:"8.0.0.0") ||
   version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.40") ||
   version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.18")){
  security_warning(port:port);
}
