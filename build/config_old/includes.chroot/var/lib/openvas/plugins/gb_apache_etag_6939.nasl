###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_etag_6939.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache Web Server ETag Header Information Disclosure Weakness
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_solution = "OpenBSD has released a patch to address this issue.

Novell has released TID10090670 to advise users to apply the available
workaround of disabling the directive in the configuration file for
Apache releases on NetWare. Please see the attached Technical
Information Document for further details.";

tag_summary = "A weakness has been discovered in Apache web servers that are
configured to use the FileETag directive. Due to the way in which
Apache generates ETag response headers, it may be possible for an
attacker to obtain sensitive information regarding server files.
Specifically, ETag header fields returned to a client contain the
file's inode number.

Exploitation of this issue may provide an attacker with information
that may be used to launch further attacks against a target network.

OpenBSD has released a patch that addresses this issue. Inode numbers
returned from the server are now encoded using a private hash to avoid
the release of sensitive information.";


desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/6939");
 script_xref(name : "URL" , value : "http://httpd.apache.org/docs/mod/core.html#fileetag");
 script_xref(name : "URL" , value : "http://www.openbsd.org/errata32.html");
 script_xref(name : "URL" , value : "http://support.novell.com/docs/Tids/Solutions/10090670.html");
 script_id(103122);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-21 17:38:45 +0100 (Mon, 21 Mar 2011)");
 script_bugtraq_id(6939);
 script_cve_id("CVE-2003-1418");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_name("Apache Web Server ETag Header Information Disclosure Weakness");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Apache ETag header fields returned to a client contain the file's inode number");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Apache" >!< banner || "ETag" >!< banner)exit(0);

etag = eregmatch(pattern:'ETag: "([^"]+)"', string:banner);
if(isnull(etag[1]))exit(0);

etag = split(etag[1], sep:"-",keep:FALSE);
if((max_index(etag)<3))exit(0);

inode = string("0x",etag[0]);
size  = string("0x",etag[1]);

inode = (hex2dec(xvalue:inode));
size  = (hex2dec(xvalue:size));

report = string("\n\nInformation that was gathered:\nInode: ", inode,"\nSize: ", size,"\n");

security_warning(port:port,data:string(desc,report));

exit(0);
