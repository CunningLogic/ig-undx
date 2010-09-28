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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.bcel.generic.*;
import org.illegalaccess.undx.Utils;
import org.illegalaccess.undx.types.LocalVar.VarType;

import sun.util.LocaleServiceProviderPool.LocalizedObjectGetter;

public class  LocalVarContext {
	private static Logger jlog = Logger.getLogger("localvarcontext");
	Hashtable<String, LocalVar> ht;
	int thisindex = -1;
	boolean isstatic = false;
	int numparam = 0;
	String classname;

	public Hashtable<String, LocalVar> getht() {
		assert (ht != null);
		return ht;
	}
	
	public Hashtable<String, LocalVar> getlocals () {
		return ht;
	}

	public LocalVar getLV(String z) {
		LocalVar lv = getht().get(z);
		if (lv == null) {
			Utils.continueAndDump("should be there:" + z);
		}
		return getht().get(z);
	}

	public LocalVar getParamType(int i) {
		for (Enumeration<String> e = getht().keys(); e.hasMoreElements();) {
			String lv = e.nextElement();
			LocalVar lve = getLV(lv);
			if (lve.name.equals("param_" + i)) {
				return lve;
			}
		}
		return null;
	}

	public static Instruction getLoadStoreInstructionFor(boolean loadtruestorefalse,
			Type t, int numjvmreg) {
		if (loadtruestorefalse) {
			if (t.equals(Type.BOOLEAN) || t.equals(Type.CHAR)
					|| t.equals(Type.INT))
				return new ILOAD(numjvmreg);
			else if (t.equals(Type.FLOAT))
				return new FLOAD(numjvmreg);
			else if (t.equals(Type.DOUBLE))
				return new DLOAD(numjvmreg);
			else if (t.equals(Type.LONG))
				return new LLOAD(numjvmreg);
			else
				return new ALOAD(numjvmreg);
		} else {
			if (t.equals(Type.BOOLEAN) || t.equals(Type.CHAR)
					|| t.equals(Type.INT))
				return new ISTORE(numjvmreg);
			else if (t.equals(Type.FLOAT))
				return new FSTORE(numjvmreg);
			else if (t.equals(Type.DOUBLE))
				return new DSTORE(numjvmreg);
			else if (t.equals(Type.LONG))
				return new LSTORE(numjvmreg);
			else
				return new ASTORE(numjvmreg);
		}

	}

	public Hashtable<String, LocalVar> getLVsByType(VarType vt) {
		Hashtable<String, LocalVar> ht = new Hashtable<String, LocalVar>();
		for (Enumeration<String> e = getht().keys(); e.hasMoreElements();) {
			String lv = e.nextElement();
			LocalVar lve = getLV(lv);
			if (lve.vt == vt) {
				ht.put(lv, lve);
			}
		}
		return ht;
	}

	public LocalVarContext(Hashtable<String, LocalVar> ht_, String sig,
			int numregs, boolean isstatic, String _classname) {
		Type[] t = Type.getArgumentTypes(sig);
		numparam = t.length;
		classname = Utils.toVMname(_classname);
		jlog.log(Level.INFO, "Sig=" + sig);
		jlog.log(Level.INFO, "Classname=" + classname);
		jlog.log(Level.INFO, "numregs={0}\n", numregs);
		jlog.log(Level.INFO, "numparam={0}\n", numparam);
		jlog.log(Level.INFO, "isstatic={0}\n", Boolean.toString(isstatic));
		ht = ht_;

		for (Enumeration<String> e = ht_.keys(); e.hasMoreElements();) {
			jlog.info("" + ht_.get(e.nextElement()));
		}
		// isstatic = _isstatic;
		// isstatic = true;
		int idxnum = 0;
		for (Enumeration<String> e = ht_.keys(); e.hasMoreElements();) {
			String idx = e.nextElement();
			LocalVar lv = ht.get(idx);
			jlog.info("*" + lv);
			if (lv.name.equals("this")) {
				// thisindex = lv.reg;
				thisindex = Integer.parseInt(idx.substring(1));
				isstatic = false;
				lv.setjvmidx(0);
				lv.setType(VarType.THIS);
				lv.type = classname;
				idxnum++;
				// Utils.stopAndDump("gibt's das noch?:"+thisindex+":"+lv);
				jlog.info(">" + lv);
				break;
			}
		}

		jlog.info("thisindex=" + thisindex);

		if (isstatic) {
			int numlocals = numregs - numparam;

			jlog.info("numregs=" + numregs);
			for (int i = 0; i < numregs; i++) {
				String idx = "v" + i;
				// for (Enumeration<String> e = ht_.keys();
				// e.hasMoreElements();) {
				// String idx = e.nextElement();
				System.out.printf("idx=%s", idx);

				LocalVar lv = getLV(idx);

				// if (lv == null || lv.getjvmidex() == -1) {
				if (i < numlocals) {
					lv = new LocalVar(i, "local_" + i, "");
					lv.vt = VarType.TEMP;
					lv.setjvmidx(numparam * 2 + i);
					ht.put(idx, lv);
				} else {
					lv = new LocalVar(i, "param_" + i, "");
					lv.vt = VarType.PARAM;
					lv.setjvmidx(i - numlocals);
					ht.put(idx, lv);
				}
				// }
			}
		}

		else {
			int numlocals = numregs - 1 - numparam;
			System.out.printf("numlocals=%d\n", numlocals);
			int shifter = 0; // alignment for Long, Double
			for (int i = 0; i < numregs; i++) {
				String idx = "v" + i;

				LocalVar lv = getLV(idx);

				// if (lv == null || lv.getjvmidex() == -1 ||
				// (!lv.name.equals("this") && lv.getjvmidex()==0)) {
				if (i == numlocals) {
					lv = new LocalVar(i, "this", "");
					lv.vt = VarType.THIS;
					lv.setjvmidx(0);
					lv.type = classname;
					ht.put(idx, lv);
				} else if (i < numlocals) {
					lv = new LocalVar(i, "local_" + i, "");
					lv.vt = VarType.TEMP;
					int myidx = numparam * 2 + i + 1;
					if (myidx == 0) {
						Utils.stopAndDump("no");
					}

					lv.setjvmidx(myidx);

					ht.put(idx, lv);
				}

				else {
					lv = new LocalVar(i, "param_" + i, "");
					lv.vt = VarType.PARAM;

					int myidx = i - numlocals;

					Type theType = t[myidx - 1];

					if (theType.getSignature().equals("J")
							|| theType.getSignature().equals("D")) {
						shifter++;
					}

					lv.type = theType.getSignature();

					if (myidx == 0) {
						Utils.stopAndDump("no");
					}
					int newindex = myidx + shifter;
					lv.setjvmidx(myidx + shifter);
					// if (lv.getjvmidex() != newindex) {
					// Utils.stopAndDump("error setting lv");
					// }
					ht.put(idx, lv);
					if (ht.get(idx).getjvmidex() != newindex) {
						Utils.stopAndDump("error setting lv");
					}

				}
				// }

			}
		}

		for (Enumeration<String> e = ht_.keys(); e.hasMoreElements();) {
			LocalVar lvc = ht_.get(e.nextElement());
			if (!isstatic) {
				if ((lvc.vt != VarType.THIS) && (lvc.getjvmidex() == 0)) {
					Utils.stopAndDump("what is this?" + lvc);
				}
			}
			jlog.fine(lvc.toString());
			// System.out.println(ht_.get(e.nextElement()));
		}

	}

	public String toString() {

		String z = "Mode:" + (isstatic ? "static" : "instance") + "\n";
		for (Enumeration<String> e = ht.keys(); e.hasMoreElements();) {
			String idx = e.nextElement();
			LocalVar lv = ht.get(idx);

			jlog.log(Level.FINE,"idx=%s", idx);
			z += idx + "/" + lv.toString() + "\n";
			// z += idx + "/" + lv.getjvmidex() + "/" + lv.reg + "/" + lv.name
			// + "/" + lv.type + "/" + lv.vt + "\n";
		}
		return z;
	}

	public int didx2jvmidx(int x) {
		return didx2jvmidxstr("v" + x);

	}

	public int didx2jvmidxstr(String x) {
		if (ht.get(x) == null) {
			jlog.info("no jvmidx for reg "+x);
		}
		return ht.get(x).getjvmidex();
	}

	public void annotateLV(String regdest, String annotype) {
		if (getLV(regdest).type.equals("")) {
			jlog.info("Setting" + regdest + " to " + annotype);
			getLV(regdest).type = annotype;
		}
	}
}
