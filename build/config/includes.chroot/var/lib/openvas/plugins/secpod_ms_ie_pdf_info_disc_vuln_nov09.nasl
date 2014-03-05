###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_pdf_info_disc_vuln_nov09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful attacks which may leads to the exposure of system information on
  the affected system.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer version 6/7/8 on Windows.";
tag_insight = "The weakness is due to an Internet Explorer including the first 63 bytes
  of the file path in the 'Title' property when converting local HTML or MHT
  files to PDF using a PDF printer. This can lead to the exposure of certain
  system information e.g. the user name.";
tag_solution = "No solution or patch is available as of 27th November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  Information Disclosure vulnerability.";

if(description)
{
  script_id(900897);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4073");
  script_bugtraq_id(37117);
  script_name("Microsoft Internet Explorer PDF Information Disclosure Vulnerability - Nov09");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37362/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/508010/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2009/11/23/internet_explorer_file_disclosure_bug/");
  script_xref(name : "URL" , value : "http://securethoughts.com/2009/11/millions-of-pdf-invisibly-embedded-with-your-internal-disk-paths/");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for MS IE version 6/7/8
if(ieVer =~ "^(6|7|8)\..*"){
  security_warning(0);
}
