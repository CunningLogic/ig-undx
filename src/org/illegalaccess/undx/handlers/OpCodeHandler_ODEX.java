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

package org.illegalaccess.undx.handlers;

import java.util.Arrays;
import java.util.logging.Logger;

import org.apache.bcel.generic.ALOAD;
import org.apache.bcel.generic.ASTORE;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.GETFIELD;
import org.apache.bcel.generic.INVOKESPECIAL;
import org.apache.bcel.generic.INVOKEVIRTUAL;
import org.apache.bcel.generic.InstructionList;
import org.apache.bcel.generic.POP;
import org.apache.bcel.generic.POP2;
import org.apache.bcel.generic.PUTFIELD;
import org.illegalaccess.undx.ClassHandler;
import org.illegalaccess.undx.DalvikCodeLine;
import org.illegalaccess.undx.DalvikToJVM;
import org.illegalaccess.undx.OpcodeSequence;
import org.illegalaccess.undx.Utils;
import org.illegalaccess.undx.types.DexClassDetails;
import org.illegalaccess.undx.types.DexFieldDetails;
import org.illegalaccess.undx.types.DexMethodDetails;
import org.illegalaccess.undx.types.FieldCollection;
import org.illegalaccess.undx.types.LocalVarContext;

public class OpCodeHandler_ODEX {
	private static Logger jlog = Logger.getLogger("odexhandler");

	public static void handle_exec_inline(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {


		int vtableidx = getvtableidx(ops);

		String[] methdata = null;
		switch (vtableidx) {
		case 1: // String.charAt()
			methdata = new String[] { "java.lang.String", "charAt", "()C" };
			break;
		case 2: // String.compareTo()
			methdata = new String[] { "java.lang.String", "compareTo",
					"(Ljava/lang/String;)I" };
			break;
		case 3: // String.compareTo()
			methdata = new String[] { "java.lang.String", "equals",
					"(Ljava/lang/String;)Z" };
			break;
		case 4: // String.compareTo()
			methdata = new String[] { "java.lang.String", "length", "()I" };
			break;
		default:
			jlog.severe("Unknown inline function");
			System.exit(-1);
			break;
		}

		System.out.print("res = ");

		int metref = cpg.addMethodref(methdata[0], methdata[1], methdata[2]);

		ClassHandler.genParameterByRegs(il, lvg, regs, methdata, cpg, metref, true);
		il.append(new INVOKEVIRTUAL(metref));

	}

	public static void handle_invoke_virtual_quick(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {

		String params = ClassHandler.getparams(regs);
		// System.out.println(vtablelit);
		int vtableidx = getvtableidx(ops);

		// System.out.println(lvg.getLV("v1"));
		// System.out.println(lvg.getLV("v2"));

		String classandmethod = "";

		System.out.println(Arrays.toString(regs));
		String thetype = lvg.getLV(regs[0]).getType();
		jlog.info("reg:" + regs[0]);
		jlog.info("type:" + thetype);
		jlog.info("idx:" + vtableidx);
		DexMethodDetails dmd = DalvikToJVM.cc.getVTableEntryForClass(thetype,
				vtableidx);
		System.out.println(dmd);
		classandmethod = dmd.getClassName() + dmd.getName() + dmd.getSig();

		// String a[] = extractClassAndMethod(classandmethod);

		if (!dmd.getSig().endsWith(")V"))
			System.out.print("res = ");
		System.out
				.printf("(%s)-> %s (%s) ;\n", regs[0], classandmethod, params);
		int metref = cpg.addMethodref(Utils.toJavaName(dmd.getClassName()),
				dmd.getName(), dmd.getSig());
		String[] a = new String[] { dmd.getClassName(), dmd.getName(), dmd.getSig() };
		ClassHandler.genParameterByRegs(il, lvg, regs, a, cpg, metref, true);
		il.append(new INVOKEVIRTUAL(metref));
		DalvikCodeLine nextInstr = dcl.getNext();

		if (!nextInstr.getOpname().startsWith("move-result")
				&& !classandmethod.endsWith(")V")) {
			if (classandmethod.endsWith(")J") || classandmethod.endsWith(")D")) {
				il.append(new POP2());
			} else {
				il.append(new POP());
			}
		}

	}

	public static int getvtableidx(String[] ops) {
		String vtablemethod = ops[2].replaceAll(",", "");
		String vtable2 = vtablemethod.replaceAll("(\\[|\\])", "");
		System.out.println(vtable2);
		int vtableidx = Integer.parseInt(vtable2, 16);
		return vtableidx;
	}

	public static void handle_iget_object_quick(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		System.out.printf("%s := (%s)-> %s ;\n", regdest, regclass, dest);

		dest = cleandest(dest);
		int off = Integer.parseInt(dest, 16);
		// DexClassDetails dfx = DalvikToJVM.cc.get(lvg.getLV(regdest).type);
		String thetype = lvg.getLV(regclass).getType();

		// DexFieldDetails dfd = DalvikToJVM.cc..getForOffset(off);
		// System.out.println(off);
		il.append(new ALOAD(jvmclass));

		// String[] classmethod = extractClassAndMethod(dest);

		DexFieldDetails dfd = getDetailsForOffset(lvg, regclass, off);
		il.append(new GETFIELD(cpg.addFieldref(Utils.toJavaName(dfd.getClassName()),
				dfd.getName(), dfd.getSig())));
		il.append(new ASTORE(jvmdest));

		String annotype = dfd.getClassName();
		lvg.annotateLV(regdest, annotype);

		// String regdest = ops[1].replaceAll(",", "");
		// String regclass = ops[2].replaceAll(",", "");
		//
		// // String regoper = ops[1].replaceAll(",", "");
		// // String regdest = ops[2].replaceAll(",", "");
		//
		//		
		// int jvmdest = lvg.didx2jvmidxstr(regdest);
		// int jvmclass = lvg.didx2jvmidxstr(regclass);
		//
		// String dest = ops[3].replaceAll(",", "");
		// System.out.printf("%s := (%s)-> %s ;\n", regdest, regclass, dest);
		// il.append(new ALOAD(jvmclass));
		// String[] classmethod = extractClassAndMethod(dest);
		//		
		//		
		// // String regoper = ops[1].replaceAll(",", "");
		// // String regdest = ops[2].replaceAll(",", "");
		// // String dest = ops[3].replaceAll(",", "");
		// System.out.printf("(%s)-> %s := %s ;\n", regdest, dest, regoper);
		// // System.out.println(lvg.getLV(regdest));
		// // System.out.println(lvg.getLV(regoper));
		// il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		// il.append(new ALOAD(lvg.didx2jvmidxstr(regoper)));
		//		
		// DexClassDetails dfx = DalvikToJVM.cc.get(lvg.getLV(regdest).type);
		// FieldCollection fc = dfx.fields;
		// for (int i = 0 ; i < fc.size(); i++) {
		// jlog.info(fc.get(i).toString());
		// };
		//		
		// if (dest.startsWith("[obj+")) {
		// dest = dest.substring(5);
		// }
		// if (dest.endsWith("]")) {
		// dest = dest.substring(0,dest.length()-1);
		// }
		// // dest = dest.replaceAll("\\\\\\[", "");
		// // dest = dest.replaceAll("\\\\\\]", "");
		// //dest = dest.replaceAll("off\\+", "");
		// int off = Integer.parseInt(dest,16);
		// jlog.info(""+off);
		// DexFieldDetails dfd = fc.getForOffset(off);
		//		
		// // il.append(i)
		//		
		// //String[] classmethod = extractClassAndMethod(dest);
		// // il.append(new PUTFIELD(cpg.addFieldref(
		// // Utils.toJavaName(dfd.classname), dfd.name,
		// // dfd.sig)));
		//		
		// jlog.info(il.toString());
		// // il.append(new PUTFIELD(cpref));
		// // System.exit(-1);
		//
		//		
		//		
		//		
		//		
		//		
		// il.append(new GETFIELD(cpg.addFieldref(
		// Utils.toJavaName(dfd.classname), dfd.name,
		// dfd.sig)));
		// il.append(new ASTORE(jvmdest));
		// System.exit(1);
	}

	private static DexFieldDetails getDetailsForOffset(LocalVarContext lvg,
			String regclass, int off) {
		DexClassDetails dfx = DalvikToJVM.cc.get(lvg.getLV(regclass).getType());
		FieldCollection fc = dfx.getFields();
		DexFieldDetails dfd = fc.getForOffset(off);
		return dfd;
	}

	public static void handle_iput_object_quick(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");
		String dest = ops[3].replaceAll(",", "");
		System.out.printf("(%s)-> %s := %s ;\n", regdest, dest, regoper);
		System.out.println(lvg.getLV(regdest));
		System.out.println(lvg.getLV(regoper));
		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ALOAD(lvg.didx2jvmidxstr(regoper)));

		FieldCollection fc = listFieldsFor(lvg, regdest);

		dest = cleandest(dest);
		// dest = dest.replaceAll("\\\\\\[", "");
		// dest = dest.replaceAll("\\\\\\]", "");
		// dest = dest.replaceAll("off\\+", "");
		int off = Integer.parseInt(dest, 16);
		jlog.info("" + off);
		DexFieldDetails dfd = fc.getForOffset(off);

		// il.append(i)

		// String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(Utils.toJavaName(dfd.getClassName()),
				dfd.getName(), dfd.getSig())));

		jlog.info(il.toString());
		// il.append(new PUTFIELD(cpref));
		// System.exit(-1);
	}

	private static FieldCollection listFieldsFor(LocalVarContext lvg,
			String regdest) {
		DexClassDetails dfx = DalvikToJVM.cc.get(lvg.getLV(regdest).getType());
		FieldCollection fc = dfx.getFields();
		for (int i = 0; i < fc.size(); i++) {
			jlog.info(fc.get(i).toString());
		}
		return fc;
	}

	static String cleandest(String dest) {
		if (dest.startsWith("[obj+")) {
			dest = dest.substring(5);
		}
		if (dest.endsWith("]")) {
			dest = dest.substring(0, dest.length() - 1);
		}
		return dest;
	}

	public static void handle_invoke_super_quick(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {
		// String reg = ops[1].replaceAll(",","");
		String params = ClassHandler.getparams(regs);
		// System.out.println(vtablelit);
		int vtableidx = getvtableidx(ops);

		// System.out.println(lvg.getLV("v1"));
		// System.out.println(lvg.getLV("v2"));

		String classandmethod = "";

		System.out.println(Arrays.toString(regs));
		String thetype = lvg.getLV(regs[0]).getType();
		jlog.info("reg:" + regs[0]);
		jlog.info("type:" + thetype);
		jlog.info("idx:" + vtableidx);
		DexMethodDetails dmd = DalvikToJVM.cc.getVTableEntryForClass(thetype,
				vtableidx);
		System.out.println(dmd);
		classandmethod = dmd.getClassName() + dmd.getName() + dmd.getSig();

		// String a[] = extractClassAndMethod(classandmethod);

		if (!dmd.getSig().endsWith(")V"))
			System.out.print("res = ");
		System.out
				.printf("(%s)-> %s (%s) ;\n", regs[0], classandmethod, params);
		int metref = cpg.addMethodref(Utils.toJavaName(dmd.getClassName()),
				dmd.getName(), dmd.getSig());
		String[] a = new String[] { dmd.getClassName(), dmd.getName(), dmd.getSig() };
		ClassHandler.genParameterByRegs(il, lvg, regs, a, cpg, metref, true);
		il.append(new INVOKEVIRTUAL(metref));
		DalvikCodeLine nextInstr = dcl.getNext();

		if (!nextInstr.getOpname().startsWith("move-result")
				&& !classandmethod.endsWith(")V")) {
			if (classandmethod.endsWith(")J") || classandmethod.endsWith(")D")) {
				il.append(new POP2());
			} else {
				il.append(new POP());
			}
		}

	}
}
