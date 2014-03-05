###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_csrf_vuln_sep10.nasl 14 2013-10-27 12:33:37Z jan $
#
# TWiki Cross-Site Request Forgery Vulnerability Sep-10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.
  Impact Level: Application";
tag_affected = "TWiki version prior to 4.3.2";
tag_insight = "Attack can be done by tricking an authenticated TWiki user into visiting
  a static HTML page on another side, where a Javascript enabled browser will
  send an HTTP POST request to TWiki, which in turn will process the request
  as the TWiki user.";
tag_solution = "Upgrade to TWiki version 4.3.2 or later,
  For updates refer to http://twiki.org/cgi-bin/view/Codev/DownloadTWiki";
tag_summary = "The host is running TWiki and is prone to Cross-Site Request
  Forgery vulnerability.";

if(description)
{
  script_id(801281);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2009-4898");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("TWiki Cross-Site Request Forgery Vulnerability Sep-10");
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
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/08/03/8");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/08/02/17");
  script_xref(name : "URL" , value : "http://twiki.org/cgi-bin/view/Codev/SecurityAuditTokenBasedCsrfFix");

  script_description(desc);
  script_summary("Check for the version of TWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get TWiki Port
twikiPort = get_http_port(default:80);
if(!twikiPort){
  exit(0);
}

## Check for TWiki versions prior to 4.3.2
if(ver = get_version_from_kb(port:twikiPort,app:"TWiki"))
{
  if(version_is_less(version: ver, test_version: "4.3.2")){
      security_hole(port:twikiPort);
  }
}
