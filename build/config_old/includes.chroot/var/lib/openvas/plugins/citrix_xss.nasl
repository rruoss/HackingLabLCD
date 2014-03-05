# OpenVAS Vulnerability Test
# $Id: citrix_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Citrix NFuse_Application parameter XSS
#
# Authors:
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from
# (C) Tenable Network Security
# Ref: Eric Detoisien <eric.detoisien@global-secure.fr>.
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote Citrix NFuse contains a flaw that allows a remote cross site 
scripting attack.

With a specially crafted request, an attacker can cause arbitrary code 
execution resulting in a loss of integrity.";

if(description)
{
 script_id(14626);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4372);
 script_cve_id("CVE-2002-0504");
 script_xref(name:"OSVDB", value:"9256");
 script_xref(name:"OSVDB", value:"9257");
  
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Citrix NFuse_Application parameter XSS";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "Test Citrix NFuse_Application parameter XSS";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# start the test

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


scripts = make_list("/launch.jsp", "/launch.asp");

found =  NULL;

foreach script (scripts)
{
 req = http_get(item:string(script,"?NFuse_Application=>alert(document.cookie);</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if("400 - Bad Request" >!< r && "alert(document.cookie);</script>" >< r )
 {
       security_hole(port);
       exit(0);
 }
}

