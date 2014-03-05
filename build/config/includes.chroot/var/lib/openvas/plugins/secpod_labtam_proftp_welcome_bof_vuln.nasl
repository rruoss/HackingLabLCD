###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_labtam_proftp_welcome_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Labtam ProFTP Welcome Message Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Attackers can exploit this issue by executing arbitrary code by tricking a
  user into connecting to a malicious FTP server and to crash an application.
  Impact Level: Application";
tag_affected = "Labtam ProFTP version 2.9 and prior on Windows.";
tag_insight = "A boundary error occurs when processing overly long welcome message sent by
  a FTP server.";
tag_solution = "Upgrade to ProFTP Version 3.0 or later.
  For updates refer to http://www.labtam-inc.com/index.php";
tag_summary = "The host is installed with Labtam ProFTP and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900980);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3976");
  script_bugtraq_id(36128);
  script_name("Labtam ProFTP Welcome Message Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36446/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9508");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2414");

  script_description(desc);
  script_summary("Check for the version of Labtam ProFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_labtam_proftp_detect.nasl");
  script_require_keys("Labtam/ProFTP/Ver");
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

pfVer = get_kb_item("Labtam/ProFTP/Ver");
if(!pfVer){
  exit(0);
}

if(version_is_less_equal(version:pfVer, test_version:"2.9")){
  security_hole(0);
}
