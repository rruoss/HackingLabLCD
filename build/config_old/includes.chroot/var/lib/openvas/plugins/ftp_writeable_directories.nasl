# OpenVAS Vulnerability Test
# $Id: ftp_writeable_directories.nasl 41 2013-11-04 19:00:12Z jan $
# Description: FTP Writeable Directories
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 TNS
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
tag_summary = "The remote FTP server contains world-writeable files

Description :

By crawling through the remote FTP server, several directories
where marked as being world writeable.

An attacker may use this misconfiguration problem to use the
remote FTP server to host arbitrary data, including possibly
illegal content (ie: Divx movies, etc...).";

tag_solution = "Configure the remote FTP directories so that they are not 
world-writeable.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";

if(description)
{
 script_id(19782);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "FTP Writeable Directories";
 script_name(name);
 
 script_description(desc);
 
 summary = "Checks for FTP directories which are world writeable";
 script_summary(summary); 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2005 TNS");
 family = "FTP";
 script_family(family);
 script_dependencies("secpod_ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("global_settings.inc");

global_var CheckedDir;
global_var WriteableDirs;
global_var Mode;
global_var Saved_in_KB;


function crawl_dir(socket, directory, level )
{
 local_var port, soc2, r, dirs,array, dir, sep, str, alreadyadded;
 if ( level > 20 ) return 0;

 if ( directory[strlen(directory) - 1] == "/" )
	sep = "";
 else
	sep = "/";

 if ( CheckedDir[directory] ) return 0;
 port = ftp_pasv(socket:socket);
 if (! port ) return 0;
 soc2 = open_sock_tcp(port);
 if (! soc2 ) return 0;
 dirs = make_list();
 
 alreadyadded=0;
 if ( Mode == MODE_WRITE )
	{
	 str = "OpenVAS" + rand_str(length:8);
	 send(socket:soc, data:'MKD ' + directory + sep + str  + '\r\n');
	 r = ftp_recv_line(socket:soc);
	 if ( r[0] == '2' )
		{
		WriteableDirs[directory] = 1;
		send(socket:soc, data:'RMD ' + directory + sep + str + '\r\n');
	 	r = ftp_recv_line(socket:soc);
		if ( ! Saved_in_KB ) {
			set_kb_item(name:"ftp/writeable_dir", value:directory);
			Saved_in_KB ++;
			alreadyadded=1;
			}
		}
	}

 send(socket:socket, data:'LIST ' + directory + '\r\n');
 CheckedDir[directory] = 1;

 r = ftp_recv_line(socket:socket);
 if ( r[0] != '1' ) {
	 close(soc2);
	 return 0;
	}

 while ( TRUE )
 {
  r = recv_line(socket:soc2, length:4096);
  if ( ! r ) break;
  if ( r[0] == 'd' )
	{
	 array = eregmatch(pattern:"([drwxtSs-]*) *([0-9]*) ([0-9]*) *([^ ]*) *([0-9]*) ([^ ]*) *([^ ]*) *([^ ]*) (.*)", string:chomp(r));
         if ( max_index(array) >= 9 )
         {
#	 if ( Mode == MODE_CHECK_PERM ) 
#		{
		 if ( array[1] =~ "^d.......w." )
			{
				if (alreadyadded == 0) 
				{
			 WriteableDirs[directory + sep + array[9]] = 1;
			 if ( ! Saved_in_KB ) {
				set_kb_item(name:"ftp/writeable_dir", value:directory + sep + array[9]);
				Saved_in_KB ++;
				}
				}
			}		 
#		}
         if ( array[9] != "." && array[9] != ".." )
	   dirs = make_list(dirs, directory + sep + array[9]);
	 }
	}
  }
 close(soc2);
 r = recv_line(socket:socket, length:4096);
 foreach dir ( dirs )
 {
   crawl_dir(socket:socket, directory:dir, level:level + 1 );
 }
 return 0;
} 
 


port = get_kb_item("Services/ftp");
if ( ! get_kb_item("ftp/anonymous") ) exit(0);
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

MODE_WRITE 		= 1;
MODE_CHECK_PERM 	= 2;


if ( safe_checks() )
 Mode = MODE_CHECK_PERM;
else 
 Mode  = MODE_WRITE;

login = "anonymous";
pwd   = "joe@";

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
if ( ! ftp_authenticate(socket:soc, user:login, pass:pwd) ) exit(0);



crawl_dir(socket:soc, directory:"/", level:0 );
ftp_close(socket:soc);

if ( isnull(WriteableDirs) ) exit(0);

foreach dir ( keys(WriteableDirs) )
 {
  report += ' - ' + dir + '\n';
 }

if ( report )
{
 report =  desc + '\n\nPlugin output :\n' +  report;
 security_warning(port:port, data:report);
}
