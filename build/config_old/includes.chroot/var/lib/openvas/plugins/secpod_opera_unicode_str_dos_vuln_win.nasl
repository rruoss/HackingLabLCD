###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_unicode_str_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Opera Unicode String Denial Of Service Vulnerability (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated for New CVE's
# - By Sharath S <sharaths@secpod.com> On 2009-09-21 #4893
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
tag_impact = "Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.
  Impact Level: Application";
tag_affected = "Opera version 9.52 and prior on Windows.";
tag_insight = "- Error caused by calling the 'window.print' function in a loop aka a
    'printing DoS attack'.
  - CPU consumption issue exists when a series of automatic submissions
    of a form containing a KEYGEN element.
  - Error exists when application fails to handle user supplied input into
    the 'write' method via a long Unicode string argument.";
tag_solution = "Upgarde to Opera Version 10 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "This host is installed with Opera and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(900803);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2577", "CVE-2008-7245", "CVE-2009-3269");
  script_name("Opera Unicode String Denial Of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3338/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/2456/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3194/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/505092/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506328/100/100/threaded");

  script_description(desc);
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

# Check for Opera version <= 9.52
if(version_is_less_equal(version:operaVer, test_version:"9.52")){
  security_warning(0);
}
