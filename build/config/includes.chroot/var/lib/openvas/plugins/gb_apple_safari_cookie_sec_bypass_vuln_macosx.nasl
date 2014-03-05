###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_cookie_sec_bypass_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apple Safari Secure Cookie Security Bypass Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to overwrite or delete arbitrary
  cookies by sending a specially crafted HTTP response through a man-in-the-
  middle attack.
  Impact Level: Application";
tag_affected = "Apple Safari versions 5.1 and prior.";
tag_insight = "The flaw is due to lack of the HTTP Strict Transport Security (HSTS)
  includeSubDomains feature, which allows man-in-the-middle attackers to
  overwrite or delete arbitrary cookies via a Set-Cookie header in an HTTP
  response.";
tag_solution = "No solution or patch is available as of 18th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to security bypass vulnerability.";

if(description)
{
  script_id(802238);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2008-7296");
  script_bugtraq_id(49136);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Apple Safari Secure Cookie Security Bypass Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/74451");
  script_xref(name : "URL" , value : "http://michael-coates.blogspot.com/2010/01/cookie-forcing-trust-your-cookies-no.html");
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2011/02/some-less-obvious-benefits-of-hsts.html");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_require_keys("AppleSafari/MacOSX/Version");
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

safVer = get_kb_item("AppleSafari/MacOSX/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions 5.1 and prior.
if(version_is_less_equal(version:safVer, test_version:"5.1")){
  security_hole(0);
}
