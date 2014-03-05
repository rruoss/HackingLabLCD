# OpenVAS Vulnerability Test
# $Id: doublecheck_std_services.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Service Detection (2nd pass)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "This plugin performs service detection.

Description :

This plugin is a complement of find_service.nasl. It attempts
to identify common services which might have been missed because
of a network problem.";

if(description)
{
 script_id(14772);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Service Detection (2nd pass)";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Identifies common services (second chance)";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Service detection";

 script_family(family);
 script_dependencies("find_service.nasl", "find_service1.nasl", "apache_SSL_complain.nasl");
 script_require_keys("Settings/ThoroughTests");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

# This script may be too slow in abnormal conditions (network glitch,
# broken configuration...)
# However, when OpenVAS is correctly configured and port scanners and 
# find_service ran well, this plugin will terminate quickly

if (! experimental_scripts || ! thorough_tests) exit(0);

# Should I add 280 (http-mgmt)?

ports = make_list(7, 19, 21, 22, 23, 25, 37, 70, 79, 80, 81, 88, 98, 
109, 110, 113, 119, 143, 220, 221, 593, 873, 901, 1080,  1085, 1109, 
1381, 2309, 2401, 3128, 3306, 5000, 5432, 8000, 8080, 8081, 
8090, 8383, 9090);
sslports = make_list(261, 443, 448, 465, 563, 585, 614, 636, 684, 902, 989, 
990, 992, 993, 994, 995, 1241, 2381, 2478, 2479, 2482, 2484, 2679, 3077, 
3078, 3269, 3471, 5007, 7135, 8443, 9443, 10000, 19201);

probes = make_list("", 'GET / HTTP/1.0\r\n\r\n', 'HELP\r\n\r\n');

timeout_n = 0; connection_n = 0;
if (! thorough_tests)
  max_timeouts = 6;
else
  max_timeouts = 9999;

missed_ssl_n = 0;
missed_svc_n = 0;

function report_missed_ssl()
{
 local_var	r;
 if ( report_verbosity < 2 ) return; 
 if (! missed_ssl_n) return;
 r = strcat('doublecheck_std_services identified ', missed_ssl_n, ' service');
 if (missed_ssl_n > 1) r += 's';
 r += 'running
on top of SSL/TLS.
The transport layer should have been found by find_service. 
You should set the "Test SSL based services" option to 
"All" or "Known SSL ports".';
 security_note(port: 0, data: r);
 missed_ssl_n = 0;	# report once only
}

function report_missed_svc()
{
 local_var	r;

 if ( report_verbosity < 2 ) return; 
 if (! missed_svc_n) return;
 r = strcat('doublecheck_std_services identified ', missed_svc_n, ' service');
 if (missed_svc_n > 1) r += 's';
 r += ' that should 
have been found by find_service. 
Something odd happened; you should increase the network 
timeout in openvasd.conf and in find_service preferences';
 security_note(port: 0, data: r);
 missed_svc_n = 0;	# report once only
}

function too_many_timeouts(interrupted)
{
  report_missed_ssl();
  report_missed_svc();

  if (report_paranoia < 2)	# Normal or Avoid FP
  {
   # No open port found - might be a mirage
   ports = get_kb_list("Ports/tcp/*");
   if (isnull(ports) || max_index(ports) == 0) exit(0);
  }

  r = strcat('While trying to identify services on common ports, 
OpenVAS got ', timeout_n, ' timeouts on ', connection_n, ' connection attempts.
The remote machine is probably firewalled. 
To get quicker tests, you should restrict the port range 
and set "Consider unscanned ports as closed".');

 if (interrupted)
  r = strcat(r, '\nNote that doublecheck_std_services.nasl was interrupted.');

  security_note(port: 0, data: r);
  exit(0);
}

if ( thorough_tests )
{
foreach p (sslports)
{
  if (get_port_state(p))
  {
    open_port = get_kb_item('Ports/tcp/'+p);
    k = "Transports/TCP/" + p;
    t = get_kb_item(k);
    if (t <= 1)
    {
      debug_print('Testing ', p, ' for SSL/TLS\n');
      s = open_sock_tcp(p, transport: ENCAPS_IP);
      connection_n ++;
      if (s)
      {
        close(s);
        debug_print('Port ', p, ' is open\n');
        if (! open_port && experimental_scripts) scanner_add_port(port: p);
      }
      else
      {
        debug_print('Port ', p, ' is closed or filtered\n');
        if (get_kb_item('/tmp/ConnectTimeout/TCP/'+p) &&
            ++ timeout_n  > max_timeouts)
           too_many_timeouts(interrupted: 1);
	# No need to try SSL/TLS if the port is closed
        continue;
      }
      for (t = ENCAPS_SSLv2; t <= ENCAPS_TLSv1; t ++)
      {
        s = open_sock_tcp(p, transport: t);
        if (s)
        {
          debug_print('Found SSL port: ', p, '\tT: ', t, '\n');
          replace_kb_item(name: k, value: t);
          close(s);
          if (open_port) missed_ssl_n ++;
          break;
        }
      }
    }
  }
 }
 report_missed_ssl();
}


foreach p (make_list(ports, sslports))
{
 if (get_port_state(p) && service_is_unknown(port: p))
 {
  open_port = get_kb_item('Ports/tcp/'+p);
  debug_print("Testing ", p, "\n");
  b = get_unknown_banner(port: p, dontfetch: 1);
  if (! b)
  {
   foreach d (probes)
   {
    s = open_sock_tcp(p);
    connection_n ++;
    if (s)
    {
     debug_print('Port ', p, ' is open\n');
     if (! open_port && experimental_scripts) scanner_add_port(port: p);
     if (d) send(socket: s, data: d);
     b = recv(socket: s, length: 4096);
     close(s);
    }
    else
    {
      debug_print('Port ', p, ' is closed or filtered\n');
      if (get_kb_item('/tmp/ConnectTimeout/TCP/'+p) &&
          ++ timeout_n  > max_timeouts)
        too_many_timeouts(interrupted: 1);
      # No need to retry connections if the port is closed
      break;
    }
    if (b) break;
   }
  }
  if (b)
  {
    found = 0;

    if (d == '') 
     replace_kb_item(name: 'FindService/tcp/'+p+'/spontaneous', value: b);
    else if ('GET' >< d)
     replace_kb_item(name: 'FindService/tcp/'+p+'/get_http', value: b);
    else
     replace_kb_item(name: 'FindService/tcp/'+p+'/help', value: b);

    bl = tolower(b);

    if (d != '' && b == d)
    {
     report_service(port: p, svc: 'echo');
     found ++;
    }

    if (b =~ "^[0-9]{3}[ -]")
    {
     if ("SMTP" >< b || "mail " >< bl)
      report_service(port: p, svc: "smtp", banner: b);
     else if ("ftp" >< bl)
      report_service(port: p, svc: "ftp", banner: b);
     else
      register_service(port: p, proto: "three_digits");
     found ++;
    }

    if (b[0] == '0xFF' && ord(b[1]) >= 251 && ord(b[1]) <= 254)
    {
     report_service(port: p, svc: "telnet", banner: b);
     found ++;
    }
    else if (b =~ "^HTTP/1\.[01] [0-9]{3}")
    {
     report_service(port: p, svc: "www", banner: b);
     if ("HTTP/1.1 502" >< b || egrep(string: b, pattern: "^Via:"))
      report_service(port: p, svc: "proxy", banner: b);
     found ++;
    }

    if (substr(b, 0, 2) == "+OK")
    {
     report_service(port: p, svc: "pop3", banner: b);
     found ++;
    }

    if (substr(bl, 0, 7) == "finger:")
    {
     report_service(port: p, svc: "finger", banner: b);
     found ++;
    }

# 0, 0: ERROR: UNKNOWN-ERROR
    if (" : error : invalid-port" >< bl || 
	": error: unknown-error" >< bl)
    {
     report_service(port: p, svc: "auth", banner: b);
     found ++;
    }

    if (r =~ "^RFB [0-9]")
    {
     report_service(port:port, svc: 'vnc', banner: b);
     found ++;
    }

    if (! found)
    {
      register_service(port: p, proto: 'unknown');
      set_unknown_banner(port: p, banner: b);
    }
    else if (open_port)
     missed_svc_n ++;
  }
 }
}
report_missed_svc();

if (timeout_n > 6) too_many_timeouts(interrupted: 0);	# Exit
