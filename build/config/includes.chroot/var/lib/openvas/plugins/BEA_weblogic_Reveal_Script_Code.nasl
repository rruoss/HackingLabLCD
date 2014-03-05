# OpenVAS Vulnerability Test
# $Id: BEA_weblogic_Reveal_Script_Code.nasl 17 2013-10-27 14:01:43Z jan $
# Description: BEA WebLogic Scripts Server scripts Source Disclosure
#
# Authors:
# Gregory Duchemin <plugin@intranode.com> 
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVSS Base
#
# Copyright:
# Copyright (C) 2001 INTRANODE
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
tag_solution = "Use the official patch available at http://www.bea.com";
tag_summary = "BEA WebLogic may be tricked into revealing the source code of JSP scripts
by using simple URL encoding of characters in the filename extension.

e.g.: default.js%70 (=default.jsp) won't be considered as a script but 
rather as a simple document.

Vulnerable systems: WebLogic version 5.1.0 SP 6

Immune systems: WebLogic version 5.1.0 SP 8";


#### REGISTER SECTION ####

if(description)
{

script_id(10715);
script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_bugtraq_id(2527);
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_tag(name:"risk_factor", value:"Medium");
#Name used in the client window.
name="BEA WebLogic Scripts Server scripts Source Disclosure";
script_name(name);



#Description appearing in the OpenVAS client window when clicking on the name.

  desc = "
  Summary:
  " + tag_summary + "
Solution:
" + tag_solution;

script_description(desc);


 
#Summary appearing in the tooltips, only one line.

summary="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
script_summary(summary);



#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);
script_copyright("Copyright (C) 2001 INTRANODE");

#Category in wich attack must be stored.

family="Web application abuses";
script_family(family);
 


#from wich scripts this one is depending:
#Services Discovery +
#Default error page configured on Web sites not showing a usual 404
#thus to prevent any false positive answer.


script_dependencies("find_service.nasl", "http_version.nasl", "webmirror.nasl");
 
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
}
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#### ATTACK CODE SECTION ####

function check(req, port)
{ 
request = http_get(item:req, port:port); 
response = http_keepalive_send_recv(port:port, data:request);
if( response == NULL ) exit(0);


#signature of Jsp.

signature = "<%=";

if (signature >< response) return(1);
 
return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

foreach dir (cgi_dirs())
{
poison = string(dir, "/index.js%70");
if (check(req:poison, port:port)) security_warning(port:port); 
}

# Try with a known jsp file
files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(isnull(files))exit(0);
files = make_list(files);
file = ereg_replace(string:files[0], pattern:"(.*js)p$",
		    replace:"\1");
poison = string(file, "%70");
if(check(req:poison, port:port))security_warning(port);
 

