###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_server_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Tivoli Directory Server Multiple Vulnerabilities
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
tag_solution = "Apply cumulative interim fix 6.2.0.3-TIV-ITDS-IF0004,
  https://www-304.ibm.com/support/docview.wss?uid=swg24030320

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.
  Impact Level: Application";
tag_affected = "IBM Tivoli Directory Server (TDS) 6.2 before 6.2.0.3-TIV-ITDS-IF0004";
tag_insight = "- IDSWebApp in the Web Administration Tool not restricting access to LDAP
    Server log files, which allows remote attackers to obtain sensitive
    information via a crafted URL.
  - The login page of IDSWebApp in the Web Administration Tool does not have
    an off autocomplete attribute for authentication fields, which makes it
    easier for remote attackers to obtain access by leveraging an unattended
    workstation.";
tag_summary = "The host is running IBM Tivoli Directory Server and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802224);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2758", "CVE-2011-2759");
  script_bugtraq_id(48512);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM Tivoli Directory Server Multiple Vulnerabilities");

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

  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/73546");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45107");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg24030320");

  script_description(desc);
  script_summary("Check for the version of IBM Tivoli Directory Server");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_require_keys("IBM/TDS/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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
if(version_in_range(version:tdsVer, test_version:"6.20", test_version2:"6.20.0.2")) {
  security_warning(0);
}
