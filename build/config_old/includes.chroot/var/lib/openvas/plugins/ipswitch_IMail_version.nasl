# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_version.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IMail account hijack
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "The remote host is running IMail web interface.
In this version, the session is maintained via the URL. It 
will be disclosed in the Referer field if you receive an
email with external links (e.g. images)";

tag_solution = "Upgrade to IMail 7.06
 or turn off the 'ignore source address in security check' option.";

# References:
#
# http://cert.uni-stuttgart.de/archive/bugtraq/2001/10/msg00082.html
#
# Date:  Sun, 10 Mar 2002 21:37:33 +0100
# From: "Obscure" <obscure@eyeonsecurity.net>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: IMail Account hijack through the Web Interface
#
#  Date:  Mon, 11 Mar 2002 04:11:43 +0000 (GMT)
# From: "Zillion" <zillion@safemode.org>
# To: "Obscure" <obscure@zero6.net>
# CC: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, "Obscure" <obscure@eyeonsecurity.net>
# Subject: Re: IMail Account hijack through the Web Interface

if(description)
{
 script_id(11271);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "IMail account hijack";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for version of IMail web interface";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("Copyright (C) 2003 Michel Arboi");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 #script_require_keys("www/IMail");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include ("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port: port);
serv = egrep(string: banner, pattern: "^Server:.*");
if(ereg(pattern:"^Server:.*Ipswitch-IMail/(([1-6]\.)|(7\.0[0-5]))", string:serv))
   security_warning(port);

