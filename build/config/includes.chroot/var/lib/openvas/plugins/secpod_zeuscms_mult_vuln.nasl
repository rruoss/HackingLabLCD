##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zeuscms_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# ZeusCMS Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the
  webserver process.
  Impact Level: Application.";
tag_affected = "ZeusCMS version 0.2";

tag_insight = "- Error in 'index.php', which allows remote attackers to include and execute
    arbitrary local files via directory traversal sequences in the page
    parameter.
  - Sensitive information under the web root is stored, which allows remote
    attackers to issue a direct request to 'admin/backup.sql' and fetch
    sensitive information.";
tag_solution = "No solution or patch is available as of 23rd February 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/zeuscms/";
tag_summary = "This host is running ZeusCMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902020);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"cvss_temporal", value:"6.7");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(38237);
  script_cve_id("CVE-2010-0680", "CVE-2010-0681");
  script_name("ZeusCMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/391047.php");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11437");

  script_description(desc);
  script_summary("Check for the version of ZeusCMS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_zeuscms_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

zeusPort = get_http_port(default:80);
if(!zeusPort){
  exit(0);
}

zeusVer = get_kb_item("www/" + zeusPort + "/ZeusCMS");
if(!zeusVer){
  exit(0);
}

zeusVer = eregmatch(pattern:"^(.+) under (/.*)$", string:zeusVer);

if(!safe_checks())
{
  sndReq = http_get(item:string(zeusVer[2], "/admin/backup.sql"), port:zeusPort);
  rcvRes = http_send_recv(port:zeusPort, data:sndReq);
  if("ZeusCMS" >< rcvRes && "CREATE TABLE" >< rcvRes && "INSERT INTO" >< rcvRes)
  {
    security_hole(zeusPort);
    exit(0);
  }
}

if(zeusVer[1] != NULL)
{
  if(version_is_equal(version:zeusVer[1], test_version:"0.2")){
    security_hole(zeusPort);
  }
}
