###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livezilla_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# LiveZilla Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Apply patch from the below link,
  http://www.securityfocus.com/archive/1/archive/1/508613/100/0/threaded

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "LiveZilla Version 3.1.8.3 and prior on all running platform.";
tag_insight = "Input passed to the 'lat', 'lng', and 'zom' parameters in 'map.php' is not
  properly sanitised before being returned to the user.";
tag_summary = "The host is running LiveZilla and is prone to Cross-Site Scripting
  Vulnerabilities.";

if(description)
{
  script_id(800418);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4450");
  script_name("LiveZilla Multiple Cross-Site Scripting Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://osvdb.org/61348");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37990");

  script_description(desc);
  script_summary("Check for the version of LiveZilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_livezilla_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

lzillaPort = get_http_port(default:80);
if(!lzillaPort){
  exit(0);
}

lzillaVer = get_kb_item("www/" + lzillaPort + "/LiveZilla");
if(!lzillaVer){
  exit(0);
}

lzillaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:lzillaVer);
if(lzillaVer[1] != NULL)
{
  if(version_is_less_equal(version:lzillaVer[1], test_version:"3.1.8.3")){
    security_warning(lzillaPort);
  }
}
