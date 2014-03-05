###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lussumo_vanilla_mult_remote_file_incl_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Lussumo Vanilla 'definitions.php' Remote File Include Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary code in a
  user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Lussumo Vanilla version 1.1.10 and prior.";
tag_insight = "The flaw is due to an error in the 'include' and 'Configuration[LANGUAGE]'
  parameters, which allows remote attackers to send a specially-crafted URL request
  to the 'definitions.php' script.";
tag_solution = "No solution or patch is available as of 15th April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://vanillaforums.org/download/";
tag_summary = "This host is running Lussumo Vanilla and is prone remote file include
  vulnerabilities";

if(description)
{
  script_id(800757);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1337");
  script_bugtraq_id(38889);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Lussumo Vanilla 'definitions.php' Remote File Include Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57147");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.com/1003-exploits/vanilla-rfi.txt");

  script_description(desc);
  script_summary("Check for the version of Lussumo Vanilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lussumo_vanilla_detect.nasl");
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

vanillaPort = get_http_port(default:80);
if(!vanillaPort){
  exit(0);
}

vanillaVer = get_kb_item("www/" + vanillaPort + "/Lussumo/Vanilla");
if(!vanillaVer){
  exit(0);
}

vanillaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vanillaVer);
if(vanillaVer[1] != NULL)
{
  if(version_is_less_equal(version:vanillaVer[1], test_version:"1.1.10")){
    security_hole(vanillaPort);
  }
}

