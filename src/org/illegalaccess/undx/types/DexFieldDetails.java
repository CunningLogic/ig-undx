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

import java.util.logging.Logger;

import org.illegalaccess.undx.Utils;

public class DexFieldDetails {
	private static Logger jlog = Logger
			.getLogger("org.illegalaccess.undx.FieldDetails");
	int number;
	int offset;
	String classname;
	String name;
	String sig;
	String access;
	String accesstext;

	public String getClassName() {
		return classname;
	}
	
	public String getName() {
		return name;
	}

	public String getSig() {
		return sig;
	}

	public DexFieldDetails(int number, int offset, String classname, String name,
			String sig, String access, String accesstext) {
		super();
		this.number = number;
		this.offset = offset;
		this.classname = classname;
		this.name = name;
		this.sig = sig;
		this.access = access;
		this.accesstext = accesstext;
		jlog.fine("Created:" + this);
	}

	public String toString() {
		// ByteArrayOutputStream baos = new ByteArrayOutputStream();
		// PrintStream f = new PrintStream(baos);
		return Utils.sprintf("[%s]+[%s]+[%s]+[%s]+[%s]+[%s]+[%s]", new Object[] {
				number, offset, classname, name, sig, access, accesstext });
		// return baos.toString();
	}

}
