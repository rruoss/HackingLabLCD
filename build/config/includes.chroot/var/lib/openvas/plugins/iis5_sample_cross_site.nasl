# OpenVAS Vulnerability Test
# $Id: iis5_sample_cross_site.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS 5.0 Sample App vulnerable to cross-site scripting attack
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The script /iissamples/sdk/asp/interaction/Form_JScript.asp 
(or Form_VBScript.asp) allows you to insert information into a form 
field and once submitted re-displays the page, printing the text you entered.  
This .asp doesn't perform any input validation, and hence you can input a 
string like:
<SCRIPT>alert(document.domain)</SCRIPT>.

More information on cross-site scripting attacks can be found at:

http://www.cert.org/advisories/CA-2000-02.html";

tag_solution = "Always remove sample applications from productions servers.
In this case, remove the entire /iissamples folder.";

if(description)
{
 script_id(10572);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);
 
 summary = "IIS 5.0 Sample App vulnerable to cross-site scripting attack";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2000 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/Form_JScript.asp", port:port);
if( res )security_warning(port);

