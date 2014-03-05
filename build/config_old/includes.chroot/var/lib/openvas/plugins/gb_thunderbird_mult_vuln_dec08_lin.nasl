###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mult_vuln_dec08_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# Mozilla Thunderbird Multiple Vulnerabilities December-08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "The host is installed with Mozilla Thunderbird and is prone to
  multiple vulnerabilities.

  Vulnerability:
  Refer to the reference links for more information on the vulnerabilities.";

tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, sensitive information disclosure, cross
  site scripting attacks and execute JavaScript code with chrome privileges.
  Impact Level: System";
tag_affected = "Thunderbird version prior to 2.0.0.19 on Linux.";
tag_solution = "Upgrade to Thunderbird version 2.0.0.19
  http://www.mozilla.com/en-US/thunderbird/all.html";

if(description)
{
  script_id(800091);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503",
                "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510",
                "CVE-2008-5511", "CVE-2008-5512");
  script_bugtraq_id(32882);
  script_name("Mozilla Thunderbird Multiple Vulnerabilities December-08 (Linux)");
  desc = "

  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-60.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-61.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-64.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-65.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-66.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-67.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-68.html");

  script_description(desc);
  script_summary("Check for the version of Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("login/SSH/success","Thunderbird/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer){
  exit(0);
}

# Thunderbird version < 2.0.0.19
if(version_is_less(version:tbVer, test_version:"2.0.0.19")){
  security_hole(0);
}
