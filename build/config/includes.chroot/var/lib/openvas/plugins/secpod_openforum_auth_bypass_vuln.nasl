###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openforum_auth_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenForum 'profile.php' Authentication Bypass Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to bypass security
  restrictions and modified user and password parameters.
  Impact Level: Application";
tag_affected = "OpenForum version 0.66 Beta and prior.";
tag_insight = "The 'profile.php' script fails to restrict access to the admin function whcih
  can be exploited via a direct request with the update parameter set to 1.";
tag_solution = "No solution or patch is available as of 26th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://openforum.sourceforge.net/";
tag_summary = "This host is installed with OpenForum and is prone to Authentication
  Bypass vulnerability.";

if(description)
{
  script_id(900927);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-7066");
  script_bugtraq_id(32536);
  script_name("OpenForum 'profile.php' Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7291");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46969");

  script_description(desc);
  script_summary("Check for the version of OpenForum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_openforum_detect.nasl");
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

opnfrmPort = get_http_port(default:80);
if(!opnfrmPort){
  exit(0);
}

opnfrmVer = get_kb_item("www/" + opnfrmPort + "/OpenForum");
opnfrmVer = eregmatch(pattern:"^(.+) under (/.*)$", string:opnfrmVer);

if(opnfrmVer[1] != NULL)
{
  if(version_is_less_equal(version:opnfrmVer[1], test_version:"0.66.Beta")){
     security_hole(opnfrmPort);
   }
}
