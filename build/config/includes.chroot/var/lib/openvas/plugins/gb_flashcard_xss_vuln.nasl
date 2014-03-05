###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flashcard_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FlashCard 'cPlayer.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an affected site.
  Impact Level: Application";
tag_affected = "FlashCard Version 2.6.5 and 3.0.1";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'id' parameter in 'cPlayer.php' that allows the attackers to execute arbitrary
  HTML and script code on the web server.";
tag_solution = "No solution or patch is available as of 19th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tufat.com/script9.htm";
tag_summary = "This host is running FlashCard and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(801211);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1872");
  script_bugtraq_id(39648);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("FlashCard 'cPlayer.php' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39484");
  script_xref(name : "URL" , value : "http://www.xenuser.org/documents/security/flashcard_xss.txt");

  script_description(desc);
  script_summary("Check if FlashCard is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

foreach dir (make_list("/", "/flashcard", "/FlashCard", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if("<TITLE>FlashCard " >< res)
  {
    ## Construct attack request
    req = http_get(item:string(dir,'/cPlayer.php?id=%22%3E%3Ciframe%20src=',
                   "http://",get_host_ip(),dir,'/register.php%3E'), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if(eregmatch(pattern: '"><iframe src=http://.*register.php>', string: res))
    {
      security_warning(port);
      exit(0);
    }
  }
}
