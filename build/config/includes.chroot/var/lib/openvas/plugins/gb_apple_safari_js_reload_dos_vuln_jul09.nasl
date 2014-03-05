###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_js_reload_dos_vuln_jul09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple Safari JavaScript 'Reload()' DoS Vulnerability - July09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code, and can
  deny the service in the vitim's system.
  Impact Level: Application";
tag_affected = "Apple Safari version 4.0.2 (4.30.19.1) and prior on Windows.";
tag_insight = "The flaw is due to a use-after-free error while calling the
  'servePendingRequests()' function in WebKit.via a crafted HTML document
  that references a zero-length '.js' file and the JavaScript reload function.";
tag_solution = "Apply the patch from the WebKit development repository.
  http://trac.webkit.org/changeset/44519";
tag_summary = "This host is installed with Apple Safari Web Browser and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800835);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2419");
  script_bugtraq_id(35555);
  script_name("Apple Safari JavaScript 'Reload()' DoS Vulnerability - July09");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51533");
  script_xref(name : "URL" , value : "http://marcell-dietl.de/index/adv_safari_4_x_js_reload_dos.php");

  script_description(desc);
  script_summary("Check for the Version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Check for Apple Safari Version <= 4.0.2 (4.30.19.1)
if(version_is_less_equal(version:safariVer, test_version:"4.30.19.1")){
  security_warning(0);
}
