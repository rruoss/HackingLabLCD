###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ffftp_untrusted_search_path_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# FFFTP Untrusted Search Path Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute an arbitrary program
  in the context of the user running the affected application.
  Impact Level: Application";
tag_affected = "FFFTP version 1.98a and prior on windows";
tag_insight = "The flaw is due to an error in application, loading executables
  (e.g. notepad.exe) in an insecure manner.";
tag_solution = "Upgrade to the FFFTP version 1.98b or later,
  For updates refer to http://sourceforge.jp/projects/ffftp/releases/";
tag_summary = "The host is running FFFTP and is prone to untrusted search path
  vulnerability.";

if(description)
{
  script_id(802505);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-3991");
  script_bugtraq_id(50412);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"creation_date", value:"2011-11-08 16:10:17 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("FFFTP Untrusted Search Path Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46649");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71020");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN62336482/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/ja/contents/2011/JVNDB-2011-000091.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Check for FFFTP version <= 1.98a (1.98.1.0)
if(version_is_less_equal(version:ftpVer, test_version:"1.98.1.0")){
  security_hole(0);
}
