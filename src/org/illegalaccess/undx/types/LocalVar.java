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

import org.illegalaccess.undx.Utils;

public class LocalVar {
		// IEEE 754 Conversion here, http://www.h-schmidt.net/FloatApplet/IEEE754de.htmls
	
	public enum VarType {
		UNKNOWN, PARAM, TEMP, THIS
	}

		int reg;
		String name;
		String type;
		private int jvmidx;
		VarType vt;

		public LocalVar(int r, String n, String t) {
			reg = r;
			name = n;
			type = t;
			jvmidx = -1;
			vt = VarType.UNKNOWN;
		}

		public void setName(String _name) {
			name =_name;
		}
		
		public VarType getVarType() {
			return vt;
		}


		public void setType(String _type) {
			type =_type;
		}
		
		public String getType() {
			return type;
		}

		public String getName() {
			return name;
		}
		
		public int getjvmidex() {
			return jvmidx;
		}
		void setjvmidx(int i) {
			if (i < 0) {
				Utils.stopAndDump(this + ":jvmidx cannot be negative:" + i);
			}
			
			if (name.equals("this") && i!=0) {
				Utils.stopAndDump(this + ":don't write to this:" + i);
				
			}
			
			if (!name.equals("this") && i==0) {
	//			Utils.stopAndDump(this + ":don't write to this:" + i);
		//		i = 27;
			}

			
			jvmidx = i;
		}

		public void setType(VarType vt_) {
			vt = vt_;
		}

		public String toString() {
			return "[reg=" + reg + "/name=" + name + "/type=" + type + "/jvmidx=" + jvmidx + "/vt=" + vt
					+ "]";
		}
	}
