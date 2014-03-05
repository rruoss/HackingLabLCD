###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shibboleth_xml_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Shibboleth XML Security Signature Key Parsing Denial of Service Vulnerability (Win)
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
tag_impact = "Successful exploitation could allow remote attackers to cause the application
  to crash, resulting in denial-of-service conditions.
  Impact Level: Application";
tag_affected = "Shibboleth versions prior to 2.4.3";
tag_insight = "The flaw is due to off-by-one error in the XML signature feature in
  Apache XML Security, allows remote attackers to cause a denial of service
  via a signature using a large RSA key, which triggers a buffer overflow.";
tag_solution = "Upgrade to Shibboleth version 2.4.3 or later,
  For updates refer to http://shibboleth.internet2.edu/downloads.html";
tag_summary = "This host is installed with Shibboleth and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802223);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_cve_id("CVE-2011-2516");
  script_bugtraq_id(48611);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Shibboleth XML Security Signature Key Parsing Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45191");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68420");
  script_xref(name : "URL" , value : "http://shibboleth.internet2.edu/secadv/secadv_20110706.txt");

  script_description(desc);
  script_summary("Check for the version of Shibboleth");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_require_keys("Shibboleth/SP/Win/Ver");
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

## Get version from KB
version = get_kb_item("Shibboleth/SP/Win/Ver");
if(version)
{
  ## Check for Shibboleth version before 2.4.3
  if(version_is_less(version:version, test_version:"2.4.3")){
    security_warning(0);
  }
}
