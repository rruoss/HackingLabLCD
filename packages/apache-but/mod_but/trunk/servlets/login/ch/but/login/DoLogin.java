/*
 * Created on Jul 25, 2005
 *
 * TODO To change the template for this generated file go to
 * Windowd - Preferences - Java - Code Style - Code Templates
 */


package ch.but.login;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;


import ch.but.log.Util;
import ch.but.repository.UserInfoBean;

/**
 * @author hobo
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates Update
 */
public class DoLogin extends HttpServlet {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 9084282891222021413L;
	@SuppressWarnings("unused")
		
	public void init() throws ServletException {
		
		try {
			UserInfoBean userInfo;
			userInfo = new UserInfoBean();		
		}
	    catch (Exception e) {
	    	Util.log("[" + getClass().getName() + "] Couldn't initialize DoLogin Servlet!", e); //$NON-NLS-1$ //$NON-NLS-2$
	        e.printStackTrace();
	        }
	}
	

	
	public void doGet(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException
	{
	   	Util.log(request.getHeader("unique_id") + "\tSSL CIPHER: \t" + request.getHeader("ssl_cipher"));
	   	Util.log(request.getHeader("unique_id") + "\tURL: \t" + request.getRequestURL());
	   	
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
	    out.append("<!DOCTYPE html PUBLIC \"-//w3c//dtd html 4.0 transitional//en\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">");
        out.append("<HTML><HEAD><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; http://www.but.ch/mod_but/login.html\"><TITLE>Global Logon Page</TITLE></HEAD>");
        out.append("<BODY></BODY></HTML>");
        out.close();
		//response.sendRedirect("http://www.but.ch/root/login/global_logon.html");
	}
	
	
	public void doPost(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException
	{
		response.setContentType("text/html");
		PrintWriter out = response.getWriter();
	    String name = request.getParameter("Username");
	    
	   	Util.log(request.getHeader("unique_id") + "\tSSL CIPHER: \t" + request.getHeader("ssl_cipher"));
	   	Util.log(request.getHeader("unique_id") + "\tURL: \t" + request.getRequestURL());
	   	Util.log(request.getHeader("unique_id") + "\tClient sent Username: \t" + request.getParameter("Username") + "\tPassword\t" + request.getParameter("Password"));

        if (name != null && name.length() > 0) {
            String value = request.getParameter("Password");
        	if (UserInfoBean.checkPassword(request, name, value)){
        		Cookie c = new Cookie("LOGON", "ok");
        		Cookie d = new Cookie("MOD_BUT_USERNAME", name);
        		Cookie e = new Cookie("MOD_BUT_AUTH_STRENGTH", "1");
        		c.setPath("/");
        		response.addCookie(c);
        		response.addCookie(d);
        		response.addCookie(e);
                out.append("<!DOCTYPE html PUBLIC \"-//w3c//dtd html 4.0 transitional//en\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">");
                out.append("<HTML><HEAD><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; http://www.but.ch/loginok/\"><TITLE>Global Logon Page</TITLE></HEAD>");
                out.append("<BODY></BODY></HTML>");
                out.close();

        	}else{
                out.append("<!DOCTYPE html PUBLIC \"-//w3c//dtd html 4.0 transitional//en\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">");
                out.append("<HTML><HEAD><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; http://www.but.ch/mod_but/login1.html\"><TITLE>Global Logon Page</TITLE></HEAD>");
                out.append("<BODY></BODY></HTML>");
                out.close();
        	}
        	
        }else{
            out.append("<!DOCTYPE html PUBLIC \"-//w3c//dtd html 4.0 transitional//en\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">");
            out.append("<HTML><HEAD><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; http://www.but.ch/mod_but/login.html\"><TITLE>Global Logon Page</TITLE></HEAD>");
            out.append("<BODY></BODY></HTML>");
            out.close();
        }
	}
}