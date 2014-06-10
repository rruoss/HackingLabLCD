/*
 * Created on Jul 26, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package ch.but.log;

import java.util.*;
/**
 * @author hobo
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

public class Util {

	 //static Calendar cal = Calendar.getInstance(TimeZone.getDefault());
	 static Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("Europe/Zurich"));
	 static String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
	 static java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(DATE_FORMAT);
	 
	  /**
	   * Log any data to System.out
	   * Prefixes EXCEPTION:
	   *
	   * @param message The message you'd like to log
	   * @param message The exception which triggered to write this log entry
	   */
	  public static void log(String message, Exception e) {
	     System.out.println("EXCEPTION:\t" + sdf.format(cal.getTime()) + "\t" + message);
	     e.printStackTrace();
	  }

	  /**
	   * Log any data to System.out
	   * Prefixes LOG:
	   *
	   * @param message The message you'd like to log
	   */
	  public static void log(String message) {
	     System.out.println("LOG:\t" + sdf.format(cal.getTime()) + "\t" + message);
	  }

	  /**
	   * Removes the first Char of any String
	   *
	   * @param stringToClean Needs the String which should be shortened$
	   *
	   * @return The Inputstring without the first char
	   */
	  public static String removeFirstChar(String stringToClean) {
	    return stringToClean.substring(1, stringToClean.length() - 1);
	  }
	}