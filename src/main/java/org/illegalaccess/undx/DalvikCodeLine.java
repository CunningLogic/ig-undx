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
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.bcel.generic.InstructionHandle;


public class DalvikCodeLine {
	
	private static Logger jlog =  Logger.getLogger(DalvikCodeLine.class.getName());

	static Pattern findregs = Pattern.compile("\\{(.+)\\}");
	String _opcode;
	String[] _rela;
	String[] _offset;
	InstructionHandle _jmpnop;
	String[] _regs;
	String _ops[];
	String _opname;
	int _mempos ; 
	DalvikCodeLine _next;
	DalvikCodeLine _prev;
	int _pos;

	DalvikCodeLine() {
		Utils.stopAndDump("should not reach here");
	}

	private static void printRegs(String[] regs) {
		for (int i = 0; i < regs.length; i++) {
			jlog.log(Level.INFO,i + ":" + regs[i]);

		}
	}

	public String toString() {
		return _pos+":"+_opcode+":"+Arrays.toString(_regs)+":"+_opname;
	}
	public DalvikCodeLine(String[] rela, String[] offset, InstructionCache ic) {
		 _rela = rela.clone();
		_offset = offset.clone();
		_opcode = rela[1];
		Matcher m = findregs.matcher(_opcode);
		boolean b = m.find(0);
		_jmpnop = ic.get(_rela[0]);

		_regs = new String[0];

		if (b) {
			_regs = m.group(1).split(", ");
			printRegs(_regs);
			_opcode = _opcode.replace(m.group(0), "|regs|");
		}
		_ops = _opcode.split("\\s+");
		for (int i = 0 ; i < _ops.length; i++ ){
			String z = _ops[i]; 
			z = z.replace(",","");
			z = z.trim();
			_ops[i]=z;
		}
		_opname = _ops[0];
		_pos = Integer.parseInt(rela[0], 16);
		_mempos = Integer.parseInt(offset[0],16);
	}

	String[] getrela() {
		return _rela;
	}
	


	String[] getoffset() {
		return _offset;
	}

	String getOpcode() {
		return _opcode;
	}

	public String getOpname() {
		//return _ops[0];
		return _opname;
	}

	String[] getRegs() {
		return _regs;
	}

	String[] getOps() {
		return _ops;
	}

	InstructionHandle getJmpNop() {
		return _jmpnop;
	}

	void setNext(DalvikCodeLine dl) {
		_next = dl;
	}

	void setPrev(DalvikCodeLine dl) {
		_prev = dl;
	}

	public int getPos() {
		return _pos;
	}
	
	public int getMemPos() {
		return _mempos;
	}

	public DalvikCodeLine getNext() {
		return _next;
	}

	public DalvikCodeLine getPrev() {
		return _prev;
	}
	
//	public String getTypeOfRegister(String v) {
//		if (_opname.startsWith("invoke")) {
//			
//		}
//		else 
//			return "";
//	}

}
