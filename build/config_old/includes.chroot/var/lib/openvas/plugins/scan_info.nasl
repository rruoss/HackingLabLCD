# OpenVAS Vulnerability Test
# $Id: scan_info.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Information about the scan
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 Tenable Network Security
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
tag_summary = "This script displays, for each tested host, information about the scan itself:

 - The version of the NVT feed
 - The type of NVT feed (Direct, Registered or GPL)
 - The version of the OpenVAS Engine
 - The port scanner(s) used
 - The port range scanned
 - The date of the scan
 - The duration of the scan
 - The number of hosts scanned in parallel
 - The number of checks done in parallel";

# TODO: This NVT is actually not relevant anymore because it is returning
# data that are available in the scanner client anyway. In the early days
# such meta information were sent via NVT results because there was lack of
# a management unit. Now there is OpenVAS Manager and Host Details.
# The NVT is now disabled by default. Eventually it needs to be decided
# whether to entirely remove it.

if(description)
{
 script_id(19506);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Information about the scan";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Displays information about the scan";
 script_summary(summary);
 
 script_category(ACT_END);
 
 
 script_copyright("Copyright (C) 2004 Tenable Network Security");
 family = "General";
 script_family(family);

 script_add_preference(name:"Be silent", type:"checkbox", value: "yes");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('plugin_feed_info.inc');
include('global_settings.inc');

be_silent = script_get_preference("Be silent");
if("yes" >< be_silent)exit(0);

# 
# If no NVT has shown anything, quietly exit
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0);

version = OPENVAS_VERSION;

if(isnull(version)) {
 version = "Unknown";
}  

report = 'Information about this scan : \n\n';
report += 'OpenVAS Scanner version : ' + version + '\n';

if ( PLUGIN_SET )
{
 report += 'NVT feed version : ' + PLUGIN_SET     + '\n';
 report += 'Type of NVT feed : ' + PLUGIN_FEED    + '\n';
}

report += 'Scanner IP : ' + this_host()    + '\n';


list = get_kb_list("Host/scanners/*");
if ( ! isnull(list) )
{
 foreach item ( keys(list) )
 {
  item -= "Host/scanners/";
  scanners += item + ' ';
 }

 report += 'Port scanner(s) : ' + scanners + '\n';
}


range = get_preference("port_range");
if ( ! range ) range = "(?)";
report += 'Port range : ' + range + '\n';

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report Verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';


start = get_kb_item("/tmp/start_time");

if ( start )
{
 time = localtime(start);
 if ( time["min"] < 10 ) zero = "0";
 else zero = NULL;

 report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' + zero + time["min"] + '\n';
}

if ( ! start ) scan_duration = 'unknown (ping_host.nasl not launched?)';
else           scan_duration = string (unixtime() - start, " sec");

report += 'Scan duration : ' + scan_duration + '\n';

log_message(port:0, data:report);
