###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fuzzylime_cms_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Fuzyylime(cms) Remote Code Execution Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when magic_quotes_gpc is disabled.

  Impact level: Application/System";

tag_affected = "Fuzyylime(cms) version 3.03a and prior.";
tag_insight = "The flaws are due to,
  - The data passed into 'list' parameter in code/confirm.php and to the
    'template' parameter in code/display.php is not properly verified
    before being used to include files.
  - Input passed to the 's' parameter in code/display.php is not properly
    verified before being used to write to a file.";
tag_solution = "No solution or patch is available as of 30th June, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://cms.fuzzylime.co.uk/st/content/download/";
tag_summary = "This host is installed with Fuzyylime(cms) which is prone to
  Remote Code Execution vulnerability.";

if(description)
{
  script_id(900584);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2176", "CVE-2009-2177");
  script_bugtraq_id(35418);
  script_name("Fuzyylime(cms) Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8978");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51205");

  script_description(desc);
  script_summary("Check for Attack string and Fuzyylime(cms) Version");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_fuzzylime_cms_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

cmsVer = get_kb_item("www/" + cmsPort + "/Fuzzylime(cms)");
cmsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:cmsVer);

if((cmsVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(cmsVer[2], "/code/confirm.php?e[]&list"+
                             "=../../admin/index.php\0"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);
  if("admin/index.php" >< rcvRes)
  {
    security_hole(cmsPort);
    exit(0);
  }
}

if(cmsVer[1] != NULL)
{
   if(version_is_less_equal(version:cmsVer[1], test_version:"3.03a")){
     security_hole(cmsPort);
   }
}
