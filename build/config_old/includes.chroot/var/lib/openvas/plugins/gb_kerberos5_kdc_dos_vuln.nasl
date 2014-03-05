###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerberos5_kdc_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Kerberos5 KDC Cross Realm Referral Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.

  Impact level: Application";

tag_solution = "Upgrade kerberos5 version 1.7.1 or Apply patch from below link,
  http://web.mit.edu/kerberos/www/
  http://web.mit.edu/kerberos/advisories/2009-003-patch.txt

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_affected = "kerberos5 version prior to 1.7.1";
tag_insight = "The flaw is caused by a NULL pointer dereference error in the KDC cross-realm
  referral processing implementation, which could allow an unauthenticated remote
  attacker to cause KDC to crash.";
tag_summary = "This host is installed with Kerberos5 and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(800441);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3295");
  script_bugtraq_id(37486);
  script_name("Kerberos5 KDC Cross Realm Referral Denial of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37977");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3652");
  script_xref(name : "URL" , value : "http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-003.txt");

  script_description(desc);
  script_summary("Check for the version of Kerberos5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kerberos5_detect.nasl");
  script_require_keys("Kerberos5/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

krbVer = get_kb_item("Kerberos5/Ver");
if(!krbVer){
  exit(0);
}

# Grep for Kerberos5 version 1.7 and prior.
if(version_is_less(version:krbVer, test_version:"1.7.1")){
  security_warning(0);
}
