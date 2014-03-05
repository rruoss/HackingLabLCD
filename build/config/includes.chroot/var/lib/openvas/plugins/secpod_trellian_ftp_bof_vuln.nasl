###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trellian_ftp_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Trellian FTP 'PASV' Response Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application.
  Impact Level: Application/System";
tag_affected = "Trellian FTP version 3.1.3.1789 and prior.";
tag_insight = "The flaw is due to improper bounds checking when processing long FTP
  'PASV' responses.";
tag_solution = "No solution or patch is available as of 26th, April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.trellian.com/ftp/index.html";
tag_summary = "This host is installed with Trellian FTP and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(901106);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1465");
  script_bugtraq_id(39598);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Trellian FTP 'PASV' Response Buffer Overflow Vulnerability");
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
  script_summary("Check for the vulnerable version of Trellian FTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("FTP");
  script_dependencies("secpod_trellian_ftp_detect.nasl");
  script_require_keys("TrellianFTP/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39370");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57778");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12152");
  exit(0);
}


include("version_func.inc");

## Get version from KB
trellianVer = get_kb_item("TrellianFTP/Version");

if(trellianVer)
{
  ##Grep for Trellian FTP version <= 3.1.3.1789
  if(version_is_less_equal(version:trellainVer, test_version:"3.1.3.1789")){
    security_hole(0);
  }
}
