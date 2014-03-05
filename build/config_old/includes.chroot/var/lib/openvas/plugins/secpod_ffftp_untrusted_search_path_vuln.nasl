###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ffftp_untrusted_search_path_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# FFFTP Untrusted Search Path Vulnerability (Windows) - Dec 11
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute an arbitrary
  program in the context of the user running the affected application.
  Impact Level: Application";
tag_affected = "FFFTP version 1.98c and prior.";
tag_insight = "The flaw is due to an error when loading executables (readme.exe) in
  an insecure manner. This can be exploited to run an arbitrary program by
  tricking a user into opening a file located on a remote WebDAV or SMB share.";
tag_solution = "Upgrade to the FFFTP version 1.98d or later,
  For updates refer to http://sourceforge.jp/projects/ffftp/releases/";
tag_summary = "The host is running FFFTP and is prone to untrusted search path
  vulnerability.";

if(description)
{
  script_id(902770);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4266");
  script_bugtraq_id(51063);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-15 15:17:47 +0530 (Thu, 15 Dec 2011)");
  script_name("FFFTP Untrusted Search Path Vulnerability (Windows) - Dec 11");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47137/");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN94002296/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000104.html");

  script_description(desc);
  script_copyright("Copyright (C) 2011 SecPod");
  script_summary("Check the version of FFFTP");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ffftp_detect.nasl");
  script_require_keys("FFFTP/Ver");
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

## Get the version from KB
ftpVer = get_kb_item("FFFTP/Ver");
if(!ftpVer){
  exit(0);
}

## Check for FFFTP version < 1.98d (1.98.4.0)
if(version_is_less(version:ftpVer, test_version:"1.98.4.0")){
  security_hole(0);
}
