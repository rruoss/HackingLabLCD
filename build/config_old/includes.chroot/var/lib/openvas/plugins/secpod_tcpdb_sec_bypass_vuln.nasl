###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tcpdb_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TCPDB Security Bypass Vulnerability
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
  restrictions and add admin accounts, via unspecified vectors in
  user/index.php script.
  Impact Level: Application";
tag_affected = "TCPDB version 3.8 and prior.";
tag_insight = "The vulnerability is due to the application not properly restricting
  access to certain administrative pages. (e.g. 'user/index.php')";
tag_solution = "No solution or patch is available as of 28th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer tohttp://www.tcpdb.com/index.php";
tag_summary = "This host is installed with TCPDB and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(900551);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1670");
  script_bugtraq_id(34866);
  script_name("TCPDB Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34966");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50371");

  script_description(desc);
  script_summary("Check for the version of TCPDB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_tcpdb_detect.nasl");
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

tPort = get_http_port(default:80);
if(!tPort){
  exit(0);
}

tcpdbVer = get_kb_item("www/" + tPort + "/TCPDB");
tcpdbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tcpdbVer);

if(tcpdbVer[1] != NULL)
{
  if(version_is_less_equal(version:tcpdbVer[1], test_version:"3.8")){
     security_hole(tPort);
   }
}
