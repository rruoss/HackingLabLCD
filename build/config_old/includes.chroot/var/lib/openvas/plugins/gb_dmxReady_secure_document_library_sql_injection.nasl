###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dmxReady_secure_document_library_sql_injection.nasl 13 2013-10-27 12:16:33Z jan $
#
# DmxReady Secure Document Library SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "DmxReady Secure Document Library version 1.2";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'ItemID' parameter in 'update.asp' that allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 06th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.dmxready.com/?product=secure-document-library";
tag_summary = "This host is running DmxReady Secure Document Library and is prone
  to SQL injection vulnerability.";

if(description)
{
  script_id(801952);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("DmxReady Secure Document Library SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102842/dmxreadysdl12-sql.txt");

  script_description(desc);
  script_summary("Check if DmxReady Secure Document Library is vulnerable to SQL Injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/SecureDocumentLibrary", "/", cgi_dirs()))
{
  req = string("GET ", dir, "/inc_securedocumentlibrary.asp HTTP/1.1\r\n",
               "Host: ", get_host_ip(),"\r\n\r\n");
  rcvRes = http_send_recv(port:port, data:req);

  ## Confirm the application
  if('<title>Secure Document Library</title>' >< rcvRes)
  {
    ## Construct the attack request
    req2 = string("GET ", dir, "/admin/SecureDocumentLibrary/DocumentLibrary" +
                  "Manager/update.asp?ItemID='1 HTTP/1.1\r\n",
                  "Host: ", get_host_ip(), "\r\n\r\n");
    rcvRes = http_send_recv(port:port, data:req2);

    ## Confirm exploit worked by checking the response
    if("error '80040e14" >< rcvRes && ">Syntax error" >< rcvRes)
    {
      security_hole(port);
      exit(0);
    }
  }
}