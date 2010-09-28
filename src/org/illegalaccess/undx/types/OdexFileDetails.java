/* 
 * Developed by Marc Schoenefeld <marc.schoenefeld@gmx.org> 
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

import java.util.List;
import java.util.logging.Logger;

class OdexFileDetails {

	private static Logger jlog = Logger
			.getLogger("org.illegalaccess.undx.OdexFileDetails");

	String file;
	List<String> deps;
	String z;
	String[] classes;

	ClassCollection theclasses;

	public OdexFileDetails(String file, List<String> deps, String z,
			String[] classes, ClassCollection theclasses) {
		super();
		this.file = file;
		this.deps = deps;
		this.z = z;
		this.classes = classes;
		this.theclasses = theclasses;
	}
}
