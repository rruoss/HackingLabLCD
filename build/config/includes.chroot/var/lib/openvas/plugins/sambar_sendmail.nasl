# OpenVAS Vulnerability Test
# $Id: sambar_sendmail.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar sendmail /session/sendmail
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 by Hendrik Scholz <hendrik@scholz.net>
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
tag_summary = "The Sambar webserver is running. It provides a web interface for sending emails.
You may simply pass a POST request to /session/sendmail and by this send mails to anyone you want.
Due to the fact that Sambar does not check HTTP referrers you do not need direct access to the server!";

tag_solution = "Try to disable this module. There might be a patch in the future.";

if(description)
{
 script_id(10415);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Low");
  name = "Sambar sendmail /session/sendmail";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Sambar /session/sendmail mailer installed ?";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");

 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if( is_cgi_installed_ka(port:port, item:"/session/sendmail") ) security_note(port);
