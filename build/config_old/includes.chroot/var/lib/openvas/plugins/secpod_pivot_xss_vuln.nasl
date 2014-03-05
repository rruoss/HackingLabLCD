###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivot_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pivot Cross Site Scripting Vulnerability
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
  restrictions by gaining sensitive information, exectue arbitrary html or
  webscript code and redirect the user to other malicious sites.
  Impact Level: Application";
tag_affected = "Pivot version 1.40.7 and prior.";
tag_insight = "- The input pased into several parameters in the pivot/index.php and
    pivot/user.php is not sanitised before being processed.
  - An error in pivot/tb.php while processing invalid url parameter reveals
    sensitive information such as the installation path in an error message.";
tag_solution = "No solution or patch is available as of 25th June, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.pivotlog.net/";
tag_summary = "This host is installed with Pivot and is prone to Cross Site
  Scripting vulnerability.";

if(description)
{
  script_id(900579);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2133", "CVE-2009-2134");
  script_bugtraq_id(35363);
  script_name("Pivot Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35363");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8941");

  script_description(desc);
  script_summary("Check for the version of Pivot");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_pivot_detect.nasl");
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

pivotPort = get_http_port(default:80);
if(!pivotPort){
  exit(0);
}

pivotVer = get_kb_item("www/" + pivotPort + "/Pivot");
pivotVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pivotVer);

if(pivotVer[2] != NULL)
{
  if(!safe_checks())
  {
    sndReq = http_get(item:string(pivotVer[2],'/pivot/index.php?menu=">'+
                      '<script>alert(123)</script><br'),port:pivotPort);
    rcvRes = http_send_recv(port:pivotPort, data:sndReq);
    if(("post" >< rcvRes) && ("<script>alert(123)</script>" >< rcvRes))
    {
      security_warning(pivotPort);
      exit(0);
    }
  }
}

if(pivotVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:pivotVer[1], test_version:"1.40.7")){
  security_warning(pivotPort);
}
