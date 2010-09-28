/* 
 * Developed by Marc Schoenefeld <marc.schoenefeld@gmx.org> 
 * Updates by Corey Benninger, Max Sobell, Zach Lanier of Intrepidus Group
 * {corey.benninger,max.sobell,zach.lanier}@intrepidusgroup.com  
 * 
 * Copyright (C) 2009 Marc Schoenefeld <http://www.illegalaccess.org> 
 * 
 * This file is a part of undx. 
 * 
 * This project is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version. 
 * 
 * This project is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details. 
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

package org.illegalaccess.undx;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import org.illegalaccess.undx.tools.FileList;
import org.illegalaccess.undx.types.ClassCollection;

/*
 * THIS CLASS IS NOT USED
 */
public class OTAAccess {

	static String path = System.getProperty("OTALocPath",
			"/Users/marc/Desktop/android_ota/ota148830/system/framework");
	static String exe = System.getProperty(DalvikToJVM.askloc);

	// def parseMethod(m):
	// proto="""
	// #0 : (in Landroid/util/EventLogFunctionalTest;)
	// name : 'disableTestReadCompoundEntry'
	// type : '()V'
	// access : 0x0001 (PUBLIC)
	// code -
	// registers : 19
	// ins : 1
	// outs : 3
	// insns size : 264 16-bit code units"""
	//
	// searchit =
	// "#(\d+)\s+\:\s\(in\s(.+?)\).+?'(.+?)'.+?'(.+?)'.+?access\s+?\:\s(.+?)\s\((.*?)\)"
	// # searchit = "\#\d+\s+\:\s\(.+?\)"
	// z = re.compile(searchit,re.I|re.S|re.M)
	// k= z.findall(m)
	//	
	// return k

	public static void main(String[] a) throws Exception {
		OTAAccess ota = new OTAAccess();
		
		//TODO: fix startdir -- never read ??? (-max 6/23)
		String startdir = a.length == 0 ? path : a[0];

		List<File> lf = new ArrayList<File>();

		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/core.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/ext.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/framework.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/android.policy.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/services.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/framework/com.google.android.gtalkservice.odex"));
		lf.add(new File("/Users/marc/Desktop/android_ota/ota148830/system/app/Talk.odex"));
		
		ClassCollection cc = new ClassCollection(lf);

		System.out.println(cc.getVTableEntryForClass("Ljava/lang/Object;", 3));
		System.out.println(cc.getVTableEntryForClass("Ljava/lang/Object;", 4));

		System.out.println(cc.getVTableEntryForClass("Ljava/lang/StringBuilder;", 59));
		System.out.println(cc.getVTableEntryForClass("Ljava/lang/StringBuilder;", 51));
		System.out.println(cc.getVTableEntryForClass("Ljava/lang/StringBuilder;", 7));

		System.out.println(cc.getVTableEntryForClass("Ljava/lang/Class;", 46));
		System.out.println(cc.getVTableEntryForClass("LSQLite/Blob;", 15));

		System.out.println(cc.getVTableEntryForClass("Lcom/google/common/Config;", 1));
		System.out.println(cc.getVTableEntryForClass(
				"Lcom/google/android/googleapps/GoogleLoginCredentialsResult$1;", 11));
		System.out.println(cc.getVTableEntryForClass(
				"Lcom/google/android/googleapps/GoogleLoginCredentialsResult;", 14));
		System.out.println(cc.getVTableEntryForClass(
				"Lcom/android/htmlviewer/HTMLViewerActivity$WebChrome;", 122));
	}

	private static Logger jlog = Logger.getLogger(OTAAccess.class.getName());
}
