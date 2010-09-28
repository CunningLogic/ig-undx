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

import java.util.logging.Logger;

import org.illegalaccess.undx.Utils;

public class DexClassDetails {
	int number;
	String superclass;
	String classdesc;
	MethodCollection meths;
	MethodCollection vtable;
	private FieldCollection fields;
	OdexFileDetails odexfile;

	private static Logger jlog = Logger
			.getLogger("org.illegalaccess.undx.DexClassDetails");

	public DexClassDetails(int number, String superclass, String classdesc,
			MethodCollection _meths, MethodCollection _vtable,
			FieldCollection _fields,OdexFileDetails _odexfile) {
		super();
		this.number = number;
		this.superclass = superclass;
		this.classdesc = classdesc;
		this.meths = _meths;
		this.vtable = _vtable;
		this.setFields(_fields);
		this.odexfile = _odexfile;
		jlog.fine(classdesc + "/" + odexfile);
	}

	public DexClassDetails(DexClassDetails cl) {
		super();
		this.number = cl.number;
		this.superclass = cl.superclass;
		this.classdesc = cl.classdesc;
		this.meths = cl.meths;
		this.vtable = cl.vtable;
		this.setFields(cl.getFields());
		this.odexfile = cl.odexfile;
	}

	public String toString() {

		String formatString = "[%s]+[%s]+[%s]+[%s]";
		Object[] objs = new Object[] { number, superclass, classdesc, meths };
		String z = Utils.sprintf(formatString, objs);
		return z;
	}

	public void setFields(FieldCollection fields) {
		this.fields = fields;
	}

	public FieldCollection getFields() {
		return fields;
	}

}
