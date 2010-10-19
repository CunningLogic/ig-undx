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
package org.illegalaccess.undx.types;

import java.util.ArrayList;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.illegalaccess.undx.Utils;

class MethodCollection extends ArrayList<DexMethodDetails> {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static Logger jlog = Logger
			.getLogger("org.illegalaccess.undx.MethodCollection");

	MethodCollection() {

	}

	MethodCollection(String parm) {

		String searchit = "\\#(\\d+)\\s+\\:\\s\\(in\\s(.+?)\\)"; // .+?'(.+?)'.+?'(.+?)'.+?access\\s+?\\:\\s(.+?)\\s\\((.*?)\\)";
		searchit = "\\#(\\d+)\\s+\\:\\s\\(in\\s(.+?)\\).+?'(.+?)'.+?'(.+?)'.+?access\\s+?\\:\\s(.+?)\\s\\((.*?)\\)";
		Pattern p = Pattern.compile(searchit, Pattern.CANON_EQ | Pattern.DOTALL
				| Pattern.MULTILINE);
		jlog.fine(parm.substring(0, Math.min(parm.length(), 250)));
		Matcher m = p.matcher(parm);
		while (m.find()) {

			int num = Integer.parseInt(m.group(1));
			jlog.fine("mnum=" + num);
			String classname = m.group(2);
			jlog.fine("mclassname=" + classname);
			String name = m.group(3);
			jlog.fine("name=" + name);
			String sig = m.group(4);
			jlog.fine("sig=" + sig);
			String access = m.group(5);
			jlog.fine("access=" + access);
			String accesstext = m.group(6);
			jlog.fine("accesstxt=" + accesstext);
			DexMethodDetails dmd = new DexMethodDetails(num, classname, name,
					sig, access, accesstext);
			add(new Integer(num), dmd);
			if (classname.equals("Ljava/lang/Class;")) {
				jlog.info(dmd.toString());
			}
		}

		jlog.fine("found:" + size() + " methods!");

	}

	public String toString() {

		String t = "[";

		for (int i = 0; i < size(); i++) {
			t = t
					+ Utils.sprintf("[%s]+[%s]+[%s]", new Object[] { i,
							get(i).name, get(i).sig });
		}

		t = t + "]";

		return t;
	}
}
