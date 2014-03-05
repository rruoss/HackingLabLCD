###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_mem_crptn_vuln_aug09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Firefox Multiple Memory Corruption Vulnerabilities Aug-09 (Win)
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary code, phishing
  attack, and can cause Denial of Service.
  Impact Level: System/Application";
tag_affected = "Firefox version before 3.0.13 or 3.5 before 3.5.2 on Windows.";
tag_insight = "Multiple memory corruption are due to:
  - Error in 'js_watch_set()' function in js/src/jsdbgapi.cpp in the JavaScript
    engine which can be exploited via a crafted '.js' file.
  - Error in 'libvorbis()' which is used in the application can be exploited
    via a crafted '.ogg' file.
  - Error in 'TraceRecorder::snapshot()' function in js/src/jstracer.cpp and
    other unspecified vectors.
  - Error in 'window.open()' which fails to sanitise the invalid character in
    the crafted URL. This allows remote attackers to spoof the address bar,
    and possibly conduct phishing attacks, via a crafted web page that calls
    window.open with an invalid character in the URL, makes document.write
    calls to the resulting object, and then calls the stop method during the
    loading of the error page.";
tag_solution = "Upgrade to Firefox version 3.0.13/3.5.2
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to multiple
  Memory Corruption vulnerabilities.";

if(description)
{
  script_id(800855);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2654");
  script_bugtraq_id(35927, 35803);
  script_name("Mozilla Firefox Multiple Memory Corruption Vulnerabilities Aug-09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36001/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-44.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-45.html");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version < 3.0.13 or 3.5 < 3.5.2
if(version_is_less(version:ffVer, test_version:"3.0.13")||
   version_in_range(version:ffVer, test_version:"3.5",
                                  test_version2:"3.5.1")){
  security_hole(0);
}
