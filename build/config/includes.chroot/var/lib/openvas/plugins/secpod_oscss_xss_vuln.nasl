###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oscss_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# osCSS 'page' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could result in a compromise of the application,
  theft of cookie-based authentication credentials, disclosure or modification
  of sensitive data.
  Impact Level: Application";
tag_affected = "osCSS Version 1.2.2 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'page' parameter in 'admin/currencies.php' that allows the attackers to
  execute arbitrary HTML and script code in the context of an affected site.";
tag_solution = "No solution or patch is available as of 27th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://download.oscss.org/";
tag_summary = "The host is running osCSS and is prone to cross site scripting
  vulnerability.";

if(description)
{
  script_id(901134);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2856");
  script_bugtraq_id(41510);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("osCSS 'page' Parameter Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40502");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60203");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1770");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_oscss.html");

  script_description(desc);
  script_summary("Check for the version of osCSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_oscss_detect.nasl");
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

## Get osCSS Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/osCSS");
ocVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(ocVer[1])
{
  ## Check for version before 1.2.2
  if(version_is_less(version:ocVer[1], test_version:"1.2.2")){
    security_warning(port);
  }
}