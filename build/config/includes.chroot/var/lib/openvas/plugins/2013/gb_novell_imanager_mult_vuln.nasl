###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_imanager_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Novell iManager Multiple Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply the patch.
  For updates refer to https://www.novell.com/support/kb/doc.php?id=7010166

  *****
  NOTE: Ignore this warning if above mentioned patch is installed.
  *****";

tag_impact = "Successful exploitation may allow remote attackers to perform unauthorized
  actions and gain access to the affected application. Other attacks are also
  possible.
  Impact Level: Application";

tag_summary = "The host is running Novell iManager and is prone to multiple unspecified
  vulnerabilities.";
tag_insight = "Multiple flaws due to,
  - Does not refresh a token after a logout action.
  - Does not require multiple steps or explicit confirmation for sensitive
    transactions.";
tag_affected = "Novell iManager version prior to 2.7 SP 6 patch 1";

if (description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
      script_tag(name : "solution" , value : tag_solution);
  }
  script_id(803626);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3268", "CVE-2013-1088");
  script_bugtraq_id(59042, 59450);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-04 16:30:14 +0530 (Tue, 04 Jun 2013)");
  script_name("Novell iManager Multiple Vulnerabilities");
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

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/92270");
  script_xref(name : "URL" , value : "http://www.osvdb.org/92269");
  script_xref(name : "URL" , value : "http://www.novell.com/support/kb/doc.php?id=7010166");
  script_summary("Check for the vulnerable version of Novell iManager");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("novell_imanager_detect.nasl");
  script_mandatory_keys("novellimanager/installed");
  script_require_ports("Services/www", 8080, 8443);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

## Variable Initialization
imanVer = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:8080);
if(!get_port_state(port)){
  exit(0);
}

imanVer = get_kb_item(string("www/", port, "/imanager"));
if(!imanVer){
  exit(0);
}

## Check for Novell iManager less than 2.7.6
if(version_is_less(version: imanVer, test_version:"2.7.6")){
  security_hole(port:port);
  exit(0);
}
