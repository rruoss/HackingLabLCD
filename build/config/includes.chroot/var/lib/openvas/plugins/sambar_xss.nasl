# OpenVAS Vulnerability Test
# $Id: sambar_xss.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Sambar XSS
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
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
tag_summary = "The Sambar web server comes with a set of CGIs are that vulnerable
to a cross site scripting attack.

An attacker may use this flaw to steal the cookies of your web users.";

tag_solution = "Delete these CGIs";

# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server

if(description)
{
 script_tag(name:"risk_factor", value:"Medium");
 script_id(80083);;
 script_version("$Revision: 16 $");
 script_cve_id("CVE-2003-1284", "CVE-2003-1285");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");

 script_bugtraq_id(7209);
  script_xref(name:"OSVDB", value:"5097");
  script_xref(name:"OSVDB", value:"5100");
  script_xref(name:"OSVDB", value:"5101");
  script_xref(name:"OSVDB", value:"5102");
  script_xref(name:"OSVDB", value:"5103");
  script_xref(name:"OSVDB", value:"5104");
  script_xref(name:"OSVDB", value:"5105");
  script_xref(name:"OSVDB", value:"5106");
  script_xref(name:"OSVDB", value:"5107");
  script_xref(name:"OSVDB", value:"5108");
  script_xref(name:"OSVDB", value:"5803");
  script_xref(name:"OSVDB", value:"5804");
  script_xref(name:"OSVDB", value:"5805");
  script_xref(name:"OSVDB", value:"5806");
  script_xref(name:"OSVDB", value:"5807");
  script_xref(name:"OSVDB", value:"5808");
  script_xref(name:"OSVDB", value:"5809");
  script_xref(name:"OSVDB", value:"5810");
  script_xref(name:"OSVDB", value:"5811");
  script_xref(name:"OSVDB", value:"5812");
  script_xref(name:"OSVDB", value:"5813");
  script_xref(name:"OSVDB", value:"5814");
  script_xref(name:"OSVDB", value:"5815");
  script_xref(name:"OSVDB", value:"5816");
  script_xref(name:"OSVDB", value:"5817");
  script_xref(name:"OSVDB", value:"5818");
  script_xref(name:"OSVDB", value:"5819");
  script_xref(name:"OSVDB", value:"5820");

 script_name("Sambar XSS");
 
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Tests for XSS attacks";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

cgis = make_list("/netutils/ipdata.stm?ipaddr=",
		 "/netutils/whodata.stm?sitename=",
		 "/netutils/finddata.stm?user=",
		 "/isapi/testisa.dll?check1=",
		 "/cgi-bin/environ.pl?param1=",
		 "/samples/search.dll?login=AND&query=",
		 "/wwwping/index.stm?wwwsite=",
		 "/syshelp/stmex.stm?bar=456&foo=",
		 "/syshelp/cscript/showfunc.stm?func=",
		 "/syshelp/cscript/showfnc.stm?pkg=",
		 "/sysuser/docmgr/ieedit.stm?path=",
		 "/sysuser/docmgr/edit.stm?path=",
		 "/sysuser/docmgr/iecreate.stm?path=",
		 "/sysuser/docmgr/create.stm?path=",
		 "/sysuser/docmgr/info.stm?path=",
		 "/sysuser/docmgr/ftp.stm?path=",
		 "/sysuser/docmgr/htaccess.stm?path=",
		 "/sysuser/docmgr/mkdir.stm?path=",
		 "/sysuser/docmgr/rename.stm?path=",
		 "/sysuser/docmgr/search.stm?path=",
		 "/sysuser/docmgr/sendmail.stm?path=",
		 "/sysuser/docmgr/template.stm?path=",
		 "/sysuser/docmgr/update.stm?path=",
		 "/sysuser/docmgr/vccheckin.stm?path=",
		 "/sysuser/docmgr/vccreate.stm?path=",
		 "/sysuser/docmgr/vchist.stm?path=",
		 "/cgi-bin/testcgi.exe?");
		 
report = NULL;

foreach c (cgis)
{
 req = http_get(item:c+"<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<script>foo</script>" >< res)
 {
  report += c + '<script>code</script>\n';
 }
}


if ( report != NULL )
{
 text = "
The following Sambar default CGIs are vulnerable to a cross-site scripting
attack. An attacker may use this flaw to steal the cookies of your
users :

" + report + "

Solution: Delete these CGIs.";

 security_warning(port:port, data:text);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
