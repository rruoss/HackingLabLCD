###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_proxy_server_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Tivoli Directory Proxy Server Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to crash an affected server,
  creating a denial of service condition.
  Impact Level: Application";
tag_affected = "IBM Tivoli Directory Server (TDS) 6.0.0.x before 6.0.0.8-TIV-ITDS-IF0007
  and 6.1.x before 6.1.0-TIV-ITDS-FP0005.";
tag_insight = "The flaw is is caused by an error in the Proxy server when constructing LDAP
  search requests, which could allow remote attackers to crash an affected
  server by sending an unbind operation during a page results search.";
tag_solution = "Apply interim fix 6.0.0.8-TIV-ITDS-IF0007 or 6.1.0-TIV-ITDS-FP0005.
  https://www-304.ibm.com/support/docview.wss?uid=swg1IO13364
  https://www-304.ibm.com/support/docview.wss?uid=swg1IO13282";
tag_summary = "The host is running IBM Tivoli Directory Server and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(801824);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-4217");
  script_bugtraq_id(44604);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM Tivoli Directory Proxy Server Denial of Service Vulnerability");

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
  script_xref(name : "URL" , value : "http://osvdb.org/68964");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42083");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2861");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Nov/1024670.html");

  script_description(desc);
  script_summary("Check for the version of IBM Tivoli Directory Server");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_require_keys("IBM/TDS/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get IBM Tivoli Directory Server version from KB
tdsVer = get_kb_item("IBM/TDS/Ver");
if(!tdsVer){
  exit(0);
}

## Check For The Vulnerable Versions
if(version_in_range(version: tdsVer, test_version: "6.0", test_version2:"6.0.0.8") ||
   version_in_range(version: tdsVer, test_version: "6.1", test_version2:"6.1.0.5")) {
  security_warning(0);
}
