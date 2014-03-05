# OpenVAS Vulnerability Test
# $Id: risearch_arbitrary_file_access.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RiSearch Arbitrary File Access
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
tag_summary = "The remote host seems to be running RiSearch, a local search engine.

This version contains a flaw that may lead to an unauthorized 
information disclosure. The issue is triggered when an arbitary 
local file path is passed to show.pl, which will disclose the 
file contents resulting in a loss of confidentiality.

An attacker, exploiting this flaw, would be able to gain access
to potentially confidential files which would be useful in 
elevating privileges on the remote machine.";

tag_solution = "Upgrade to the latest version of this software.";

# Ref: IRM PLC <advisories at irmplc dot com>

if(description)
{
script_id(14222);
script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_cve_id("CVE-2004-2061");
script_bugtraq_id(10812);

 script_xref(name:"OSVDB", value:"8266");

 name = "RiSearch Arbitrary File Access";

 script_name(name);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;

 script_description(desc);
 
 summary = "Determines the presence of RiSearch show.pl";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web application abuses");
 
 script_dependencies("http_version.nasl");
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

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( cgi_dirs() )
{
	req = http_get(port:port, item:dir + "/search/show.pl?url=file:/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
 	if ( "root:" >< res &&
      		"adm:" >< res ) 
	{
	 	security_hole(port);
	 	exit(0);
	}
}
