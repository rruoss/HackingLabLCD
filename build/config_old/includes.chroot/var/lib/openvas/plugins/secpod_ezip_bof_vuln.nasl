###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ezip_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# eZip Buffer Overflow Vulnerability.
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
tag_impact = "Successful exploit will allow the attacker to execute arbitrary code on
  the system to cause the application to crash.
  Impact Level: Application";
tag_affected = "eZip version 3.0 and prior on Windows.";
tag_insight = "A boundary check error while processing specially crafted .zip compressed
  files leads to a stack based buffer overflow.";
tag_solution = "No solution or patch is available as of 23rd March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.edisys.com/";
tag_summary = "The host is installed with eZip Wizard and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(900525);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-24 05:22:25 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1028");
  script_bugtraq_id(34044);
  script_name("eZip Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8180");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49148");

  script_description(desc);
  script_summary("Check for the version of eZip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ezip_detect.nasl");
  script_require_keys("eZip/Version");
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

ezipVer = get_kb_item("eZip/Version");
if(!ezipVer){
  exit(0);
}

if(version_is_less_equal(version:ezipVer, test_version:"3.0")){
  security_hole(0);
}
