###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_js_uri_xss_vuln_sep09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Product(s) 'javascript:' URI XSS Vulnerability - Sep09 (Win)
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
tag_impact = "Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.
  Impact Level: Application";
tag_affected = "Mozilla, Firefox version 3.0.13 and prior, 3.5, 3.6/3.7 a1 pre
           Moziila Browser 1.7.13 and prior,
           Seamonkey 1.1.17 on Windows.";
tag_insight = "Application fails to sanitise the 'javascript:' and 'data:' URIs in Refresh
  headers or Location headers in HTTP responses, which can be exploited via
  vectors related to injecting a Refresh header or Location HTTP response header.";
tag_solution = "No solution or patch is available as of 04th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.org/";
tag_summary = "This host is installed with Mozilla Product(s) and is prone to
  Cross-Site Scripting vulnerability.";

if(description)
{
  script_id(800885);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3010", "CVE-2009-3014");
  script_name("Mozilla Product(s) 'javascript:' URI XSS Vulnerability - Sep09 (Win)");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3315/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3323/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3373/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3386/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506163/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Mozilla products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_mozilla_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver",
                      "Mozilla/Win/Ver");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version <= 3.0.13 or 3.5 or 3.6 a1 pre or 3.7 a1 pre
  if(version_is_less_equal(version:ffVer, test_version:"3.0.13")||
     version_is_equal(version:ffVer, test_version:"3.5"))
  {
    security_warning(0);
    exit(0);
  }
}
else
{
  if(registry_key_exists(key:"SOFTWARE\Mozilla\Minefield"))
  {
    foreach item (registry_enum_keys(key:"SOFTWARE\Mozilla\Minefield"))
    {
      ver = eregmatch(pattern:"([0-9.]+a1pre)", string:item);

      # Firefox 3.6a1pre or 3.7a1pre Version check
      if(ver =~ "^3\.[6|7]a1pre")
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version 1.1.17
  if(version_is_equal(version:smVer, test_version:"1.1.17"))
  {
    security_warning(0);
    exit(0);
  }
}

# For Mozilla Browser
mbVer = get_kb_item("Mozilla/Win/Ver");
if(mbVer)
{
  # Check for Mozilla Browser Version 1.7.13 and prior
  if(version_is_less_equal(version:mbVer, test_version:"1.7.13")){
    security_warning(0);
  }
}
