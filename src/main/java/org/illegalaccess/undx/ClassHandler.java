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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.bcel.Constants;
import org.apache.bcel.classfile.AccessFlags;
import org.apache.bcel.classfile.Constant;
import org.apache.bcel.classfile.ConstantDouble;
import org.apache.bcel.classfile.ConstantFloat;
import org.apache.bcel.classfile.ConstantClass;
import org.apache.bcel.classfile.Field;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.LocalVariableTable;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;
import org.illegalaccess.undx.handlers.OpCodeHandler_ODEX;
import org.illegalaccess.undx.types.DexMethodDetails;
import org.illegalaccess.undx.types.LocalVar;
import org.illegalaccess.undx.types.LocalVarContext;
import org.illegalaccess.undx.types.LocalVar.VarType;

//import com.sun.tools.javac.util.Log;

import sun.util.logging.resources.logging;

public class ClassHandler {

	static Logger jlog = Logger.getLogger(ClassHandler.class.getName());

	static Pattern classnamepattern = Pattern.compile("'L(.+);");
	static Pattern accessflagpattern = Pattern.compile("0x(.+) \\((.+)\\)");
	static Pattern methodtypes = Pattern.compile("\\((.+)\\)(.+)");
	static Pattern re_classdesc = Pattern
			.compile("Class descriptor  : 'L(.+);'");
	static Pattern re_superclass = Pattern.compile("Superclass\\s+: 'L(.+);'");
	static Pattern re_accessflags = Pattern
			.compile("Access flags      : 0x(.+) \\((.+)\\)");
	static Pattern re_fields = Pattern.compile(
			"Static fields(.+?)Direct methods", Pattern.DOTALL
					| Pattern.MULTILINE);

	static Pattern re_interfaces = Pattern.compile(
			"Interfaces(.+?)Static fields", Pattern.DOTALL | Pattern.MULTILINE);
	static Pattern re_q = Pattern.compile("'L(.+);'");

	static Pattern re_methods = Pattern.compile(
			"Direct methods(.+?)source_file_idx", Pattern.DOTALL
					| Pattern.MULTILINE);

	static Pattern re_locals = Pattern.compile("0x(.+?)$", Pattern.MULTILINE
			| Pattern.DOTALL);

	private static final String str_TYPE = "type";
	private static final String str_ACCESS = "access";

	// Instance fields

	String thefields = "";
	String classname = "";
	String accessstring = "";
	String theklass = "";
	String superclass = "";
	JarOutputStream out;
	List<String> l;

	public static String getparams(String[] a) {
		String ret = "";
		if (a.length == 1) {
			return "<void>";
		} else {
			for (int i = 1; i < a.length; i++) {
				ret = ret + a[i] + ",";

			}
			ret = ret.substring(0, ret.length() - 1);
			return ret;
		}

	}

	static String getstaticparams(String[] a) {
		String ret = "";
		if (a.length == 0) {
			return "<void>";
		} else {
			for (int i = 0; i < a.length; i++) {
				ret = ret + a[i] + ",";

			}
			ret = ret.substring(0, ret.length() - 1);
			return ret;
		}

	}

	static String dashToDot(String vmname) {
		return vmname.replace('/', '.');
	}

	APKAccess _apa;

	void setAPA(APKAccess apa) {
		_apa = apa;
	}

	APKAccess getAPA() {
		return _apa;
	}

	public String getClassName() {
		return classname;
	}

	public ClassHandler(String _outpref, String _theklass,
			JarOutputStream _out, APKAccess apa) throws IOException {
		outpref = _outpref;
		setAPA(apa);
		theklass = _theklass;
		out = _out;
		// Class descriptor : 'Lcom/androidcan/asudoku/Coordinates;'

		classname = dashToDot(getFromRE(theklass, re_classdesc));
		// classname = getFromRE(theklass, re_classdesc);
		jlog.info("class:" + classname);
		accessstring = getFromRE(theklass, re_accessflags);
		jlog.info("access:" + accessstring);

		// String superclass = "";
		superclass = dashToDot(getFromRE(theklass, re_superclass));

		jlog.info("super:" + superclass);

		String theinterfaces = getFromRE(theklass, re_interfaces);

		jlog.info("interfaces:***" + theinterfaces + "***");

		// Interfaces -
		// #0 : 'Ljava/lang/Runnable;'
		// Static fields

		Matcher qm = re_q.matcher(theinterfaces);
		l = new ArrayList<String>();
		while (qm.find()) {
			l.add(dashToDot(qm.group(1)));
		}

		// ClassGen cg = new ClassGen("HelloWorld",
		// "java.lang.Object",
		//
		// "<generated>",

		// ACC_PUBLIC | ACC_SUPER, null);
		// JarFile jf = new JarFile("gen/gen.jar");

		thefields = getFromRE(theklass, re_fields);

	}

	ClassGen m_currentClassGen = null;
	ConstantPoolGen m_currentConstantPool = null;
	InstructionFactory m_currentInstructionFactory = null;
	String outpref = "";

	public void doit() throws IOException {
		String access = "";
		String name = "";
		String type = "";

		String sourcename = classname.replace("/", ".") + ".java";
		/* TODO: nicht alles ist public */

		jlog.info("c=" + classname);
		jlog.info("s=" + superclass);
		jlog.info("so=" + sourcename);
		// Utils.stopAndDump("asas");
		ClassGen cg = new ClassGen(classname, superclass, sourcename,
				Constants.ACC_PUBLIC | Constants.ACC_SUPER, null);

		m_currentClassGen = cg;
		ConstantPoolGen pg = cg.getConstantPool();
		m_currentConstantPool = pg;

		InstructionFactory ifac = new InstructionFactory(m_currentClassGen,
				m_currentConstantPool);
		m_currentInstructionFactory = ifac;
		for (int i = 0; i < l.size(); i++) {
			cg.addInterface(l.get(i));
			jlog.info(l.get(i));
		}

		BufferedReader br = new BufferedReader(new StringReader(thefields));

		String tline = "";
		while ((tline = getNextTrimmedLine(br)).length() > 0) {

			if (tline.startsWith("#")) {
				String num = tline.substring(1);
				tline = getNextTrimmedLine(br);
				jlog.info("Method " + num);

			}
			// try {
			jlog.info(tline);

			KeyValue kv = new KeyValue(tline);
			String key = kv.getKey();
			String value = kv.getValue();
			if (key.equals(str_TYPE)) {
				type = value.replaceAll("'", "");
			}

			if (key.equals("name")) {
				name = value.replaceAll("'", "");
			}

			if (key.equals("access")) {
				access = value.split(" ")[0].substring(2);
			}
			jlog.info(kv.getKey() + "=>" + kv.getValue());

			if (type.length() * name.length() * access.length() != 0) {
				Type t = Type.getType(type);
				int access2 = Integer.parseInt(access, 16);
				FieldGen fg = new FieldGen(access2, t, name, pg);
				Field f = fg.getField();
				cg.addField(f);
				jlog.info(f.toString());
				type = "";
				name = "";
				access = "";
			} else {
				jlog.info("val=" + type.length() * name.length()
						* access.length() + "/" + name + "/" + access + "/"
						+ type);
			}

		}
/*
		String tag = "undx_shameless_plug";
		int myaccessflag = 2;
		FieldGen fgshamelessplug = new FieldGen(myaccessflag,
				Type.getType("Z"), tag, pg);
		Field f = fgshamelessplug.getField();
		cg.addField(f);
		// Date d = new Date();
		int year = Calendar.getInstance().get(Calendar.YEAR);
		int month = Calendar.getInstance().get(Calendar.MONTH);
		int date = Calendar.getInstance().get(Calendar.DAY_OF_MONTH);
		int hours = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
		int mins = Calendar.getInstance().get(Calendar.MINUTE);
		// tag = "generated_on_" + (1900+d.getYear()) + "_" + (1+d.getMonth()) +
		// "_"
		// + d.getDate() + "_" + d.getHours() + "_" + d.getMinutes();
		tag = "generated_on_" + ( 1900 + year) + "_" + (1 + month) + "_"
				+ date + "_" + hours + "_" + mins;
		fgshamelessplug = new FieldGen(myaccessflag, Type.getType("Z"), tag, pg);
		f = fgshamelessplug.getField();
		cg.addField(f);

		tag = "for_info_on_the_undx_tool_contact_marc_schoenefeld_at_gmx_dot_org";
		fgshamelessplug = new FieldGen(myaccessflag, Type.getType("Z"), tag, pg);
		f = fgshamelessplug.getField();
		cg.addField(f);
*/
		String themethods = getFromRE(theklass, re_methods);

		// br = new BufferedReader(new StringReader(themethods));

		String[] mm = themethods.split("\\#\\d+\\s+:");
		jlog.info("Methods" + mm.length);

		for (String amethod : mm) {
			// jlog.info("***" + amethod + "*****");
			if (amethod.contains("locals")) {
				String localtable = amethod.split("locals")[1];

				// 0x0000 - 0x0006 reg=0 this
				// Lcom/abc/xapp/aClassXYZ;

				Matcher ma_locals = re_locals.matcher(localtable);

				Hashtable<String, LocalVar> locals = new Hashtable<String, LocalVar>();
				int j = 0;
				while (ma_locals.find()) {
					String locinfo = ma_locals.group();
					jlog.info(ma_locals.group());
					String localinf[] = locinfo.split(" ");
					int locreg = Integer.parseInt(localinf[3].replace("reg=",
							""));
					String locname = localinf[4];
					String loctype = localinf[5];
					LocalVar lv = new LocalVar(locreg, locname, loctype);
					lv.setType(VarType.TEMP);
					locals.put("v" + locreg, lv);
					jlog.info("put=" + lv + "/" + (j++));
				}
				BufferedReader br2 = new BufferedReader(new StringReader(
						amethod));

				ArrayList<String> al = getArrayListUntilEndmarker(br2,
						"insn size", false);
				String thetype = fromKey(al, str_TYPE);
				boolean isStatic = fromKey(al, str_ACCESS).contains("STATIC");
				int numregs = Integer.parseInt(fromKey(al, "registers"));

				jlog.info(thetype);
				// System.exit(0);
				LocalVarContext lvg = new LocalVarContext(locals, thetype,
						numregs, isStatic, classname);
				// jlog.info(lvg);
				// jlog.info("MMMMMMMMMMMMMMMMMMMMMMMMMMMm");
				// jlog.info("amethod="+amethod);
				// jlog.info("MMMMMMMMMMMMMMMMMMMMMMMMMMMm");

				br2 = new BufferedReader(new StringReader(amethod));
				MethodGen mg = getMethodDetail(br2, pg, classname, lvg);
				// if (mg.getName().equals("xbaseDraw")
				// || mg.getName().equals("xfillField")) {
				// mg = null;
				// }
				// jlog.info(lvg);

				if (mg != null) {
					jlog.info("gathered details for method:" + mg.getName()
							+ ":" + mg.getSignature());
					// jlog.info("gathered details with sig:"
					// + mg.getSignature());
					try {
						mg.setMaxStack();
					} catch (Exception e) {

						e.printStackTrace(System.out);
						mg.setMaxStack(150);
					}

					mg.setMaxLocals();

					jlog.info("Setting maxStack =" + mg.getMaxStack());
					jlog.info("Getting maxLocals=" + mg.getMaxLocals());
					jlog.info("Getting localvar length=" + mg.getLocalVariables().length);

					// jlog.info("****************");
					// InstructionList il = mg.getInstructionList();

					// jlog.info(il);
					// jlog.info("****************");
					/*
					 * InstructionList il = mg.getInstructionList();
					 * il.append(new NOP()); il.append(new RETURN());
					 */
					// mg.addLocalVariable("karl", Type.getType("I"), null,
					// null);
					// jlog.info("mg=" + mg);
					for (LocalVariableGen localVariableGen : mg
							.getLocalVariables()) {
						jlog.info("lv=" + localVariableGen.getName() + "\t"
								+ localVariableGen.getIndex() + "\t"
								+ localVariableGen.getType());
					}
/*					if (mg.getLocalVariables().length > mg.getMaxLocals()) {
						Utils.stopAndDump("VarTable too long");
					}*/
					LocalVariableTable x = mg.getLocalVariableTable(pg);

					jlog.info("lvt.length=" + x.getLength());

					// if (mg.getMethod().getName().equals("onCompletion")) {
					// Utils.stopAndDump("onC");
					// }
					Method meth = mg.getMethod();
					cg.addMethod(meth);
					jlog.info("Meth=" + meth);
					// System.exit(0);

				}

				// jlog.info("//**" + amethod + "***//");

			}
		}

		String sourcefile = new KeyValue(tline).getValue();

		// Output
		jlog.info(accessstring + " class " + classname + " extends "
				+ superclass);
		for (int i = 0; i < l.size(); i++) {
			jlog.info("implements " + l.get(i) + "\n");
		}
		jlog.info("//" + sourcefile);
		cg.setConstantPool(pg);

		dump(cg.getJavaClass(), out);

	}

	private String getFromRE(String theklass, Pattern p) {
		String classname = "";
		Matcher m = p.matcher(theklass);
		if (m.find()) {
			classname = m.group(1);
		}
		return classname;
	}

	private void dump(JavaClass jc, JarOutputStream out) throws IOException {
		String classFile = jc.getClassName().replace('.', File.separatorChar)
				.concat(".class");
		OutputStream stream = null;
		if (out == null) {
			File file = new File(outpref, classFile);
			File directory = file.getParentFile();
			if (directory != null) {
				boolean b = directory.mkdirs();
				if (b) {
					jlog.info(directory + " was created");
				}
			}
			stream = new FileOutputStream(file);
		} else {
			out.putNextEntry(new JarEntry(classFile));
			stream = out;
		}
		jlog.log(Level.FINE, classFile + " dumped");
		final ByteArrayOutputStream thisout = new ByteArrayOutputStream(2048);
		jc.dump(thisout);
		thisout.writeTo(stream);
	}

	private String fromKey(ArrayList<String> al, String thekey) {
		for (String line : al) {
			KeyValue kv = new KeyValue(line.trim());
			String key = kv.getKey();
			String value = kv.getValue();
			if (key.equals(thekey)) {
				return value.replaceAll("'", "");
				// System.exit(1);
			}
		}
		return "";
	}

	private MethodGen getMethodMeta(ArrayList<String> al, ConstantPoolGen pg,
			String classname) {
		String type = "";
		String name = "";
		String access = "";
		boolean allfound = false;
		for (String line : al) {
			KeyValue kv = new KeyValue(line.trim());
			String key = kv.getKey();
			String value = kv.getValue();
			if (key.equals(str_TYPE)) {
				type = value.replaceAll("'", "");
				// System.exit(1);
			}

			if (key.equals("name")) {
				name = value.replaceAll("'", "");
			}

			if (key.equals("access")) {
				access = value.split(" ")[0].substring(2);
			}
			jlog.info(kv.getKey() + "=>" + kv.getValue());
			// System.exit(-1);
			// System.exit(-1);

			allfound = (type.length() * name.length() * access.length() != 0);
			if (allfound) {
				break;
			}
		}

		if (allfound) {
			Matcher m = methodtypes.matcher(type);
			jlog.info("type=" + type);
			jlog.info(Integer.toString(m.groupCount()));
			boolean n = m.find();
			jlog.info(Boolean.toString(n));
			jlog.info(Arrays.toString(Type.getArgumentTypes(type)));

			jlog.info(type);
			Type[] rt = Type.getArgumentTypes(type);
			Type t = Type.getReturnType(type);

			int access2 = Integer.parseInt(access, 16);
			jlog.info(Arrays.toString(rt));
			jlog.info(t.toString());
			MethodGen fg = new MethodGen(access2, t, rt, null, name, classname,
					new InstructionList(), pg);
			return fg;

			// stopAndDump("rotten signature");

		}
		jlog.info("a:" + type + ":" + name + ":" + access);
		Utils.stopAndDump("missing metadata for method");
		return null;

	}

	static boolean fixArrayList(ArrayList<String> xl) {
		boolean fixed = false;
		for (int i = 0; i < xl.size() - 1; i++) {
			jlog.info("i=" + xl.get(i));
			if (xl.get(i).contains("const-string")
					&& xl.get(i + 1).startsWith("\"")) {
				String str1 = xl.get(i) + "\\n\"";
				xl.set(i, str1);
				xl.remove(i + 1);
				fixed = true;
				jlog.info("**fixed:" + str1 + ":" + i);
				// i--;
			}
		}
		return fixed;
	}

	private MethodGen getMethodDetail(BufferedReader lr, ConstantPoolGen cpg,
			String classname, LocalVarContext locals) {

		ArrayList<String> bl = getArrayListUntilEndmarker(lr, "insns size",
				false);
		MethodGen mg = getMethodMeta(bl, cpg, classname);

		// String endmarker = "catches";
		ArrayList<String> al = getArrayListUntilEndmarker(lr, "catches", true);
		// boolean ret = fixArrayList(al);
		// jlog.info("fixed:" + ret);
		InstructionList il = mg.getInstructionList();
		InstructionCache ic = new InstructionCache(il);
		int numcatches = 0;
		// preparse, build the jump skeleton
		// ArrayList<String[]> bl1 = new ArrayList<String[]>();
		OpcodeSequence bl1 = new OpcodeSequence();
		for (String karl : al) {
			String[] s1 = karl.split("\\|");

			if (s1.length > 1) {
				String[] offsetandcode = s1[0].split(": ");
				// String[] relativeandmne = s1[1].split(": ");
				String thecode = s1[1];
				String[] relativeandmne = new String[2];
				relativeandmne[0] = thecode.substring(0, 4);
				relativeandmne[1] = thecode.substring(6);
				// jlog.info(relativeandmne[0]);
				// if (relativeandmne.length > 1) {
				if (!thecode.startsWith("[")) {
					InstructionHandle jmpnop = il.append(new NOP());

					ic.put(relativeandmne[0], jmpnop);
					jlog.info(relativeandmne[0] + "/" + jmpnop);

					DalvikCodeLine dl = new DalvikCodeLine(relativeandmne,
							offsetandcode, ic);
					bl1.add(dl);

				}
			}
			if (s1.length > 0) {
				if (s1[0].trim().startsWith("catches")) {
					jlog.info(Arrays.toString(s1));
					String p = s1[0].split(":")[1].trim();
					jlog.info(p);
					if (p.equals("(none)")) {
						numcatches = 0;
					} else {
						numcatches = Integer.parseInt(p);
					}
					jlog.info("numcatches=" + numcatches);
				}
			}

		}

		for (DalvikCodeLine dcl : bl1) {

			// erstrebenswert:
			// Framework gibt aktuelle Zeile, vorherige Zeile, etc.
			// Idee: Textzeilen als (r/o) verk. Liste mit Pointer auf aktueller
			// Zeile

			// jlog.info("codeline:" + karl);
			// String[] s1 = karl.split("\\|");
			//
			// if (s1.length > 1) {
			String[] relativeandmne = dcl.getrela();
			String[] offsetandcode = dcl.getoffset();
			if (relativeandmne.length > 1) {
				jlog.info("offset:" + relativeandmne[0] + " opcode:"
						+ relativeandmne[1]);
				String opcode = dcl.getOpcode();

				// String[] regs = dcl.getRegs();

				InstructionHandle jmpnop = dcl.getJmpNop();

				String[] ops = dcl.getOps();
				InstructionList il2 = doOpcodes(mg, il, dcl, bl1, cpg, ic,
						locals);

				// InstructionList il2 = doOpcodes(mg, regs, ops, offsetandcode,
				// relativeandmne, cpg, ic, locals);
				if (jmpnop.getNext() != null) {
					il.insert(jmpnop.getNext(), il2);
				} else {
					il.append(il2);
				}

				il.setPositions();
			} else {

				Utils.stopAndDump("should not happen");

				jlog.info("Length:"+relativeandmne.length);
				jlog.info("Offset:"+offsetandcode.length);

			}

		}

		jlog.info("numcatches:" + numcatches);
		// String exceptions = ;
		ArrayList<String> alex = getArrayListUntilEndmarker(lr, "positions",
				false);
		jlog.info("excp start");

		int i_exp = 0;
		String[] positions = new String[0];
		for (String z : alex) {
			if (z.startsWith("0x")) { // we have a block
				positions = z.split("-");
				positions[0] = positions[0].replaceAll("0x", "");
				positions[1] = positions[1].replaceAll("0x", "");
			} else {
				String[] handler = z.split("->");
				// jlog.info(Arrays.toString(handler));
				String excp = handler[0];
				handler[1] = handler[1].replaceAll("0x", "");

				ObjectType theExp = null;
				try {
					theExp = (ObjectType) Type.getType(excp);
				} catch (Exception e) {
					// jlog.info("catchall exception for " +
					// positions[0]
					// + " to " + positions[1] + ":" + e + ":" + excp);
					theExp = (ObjectType) Type.getType("Ljava/lang/Throwable;");
				}
				// jlog.info("hallo:" + theExp + ":" + positions[0]);
				jlog.info("*" + Arrays.toString(positions) + "*");
				positions[0] = positions[0].trim();
				positions[1] = positions[1].trim();
				InstructionHandle ih_start = ic.get(positions[0].trim());

				InstructionHandle ih_end = ic.get(positions[1].trim());

				jlog.info("*" + Arrays.toString(positions) + "*"
						+ ih_end + ":" + ih_start);
				if ((ih_end != null)) {
					if (ih_end.getNext() != null) {
						while ((ih_end.getNext() != null)
								&& (ih_end.getNext().getInstruction() != null)
								&& !(ih_end.getNext().getInstruction() instanceof NOP)) {
							ih_end = ih_end.getNext();
						}
					}
				} else {
					InstructionHandle lauf = ih_start;
					while (lauf.getNext() != null) {
						lauf = lauf.getNext();
					}
					ih_end = lauf;
				}
				InstructionHandle ih_handler = ic.get(handler[1].trim())
						.getNext();
				// jlog.info(positions[0] + ":" + positions[1] + ":"
				// + excp + ":" + handler[1]);
				// jlog.info(ih_start + ":" + ih_end + ":" + excp + ":"
				// + ih_handler);
				i_exp++;

				mg.addExceptionHandler(ih_start, ih_end, ih_handler, theExp);

			}
		}
		/*
		 * 
		 * for (int i = 0; i < alex.size(); i = i + 2) { String z =
		 * alex.get(i).replaceAll("0x", ""); String[] positions = z.split("-");
		 * z = alex.get(i + 1).replaceAll("0x", ""); String[] handler =
		 * z.split("->");
		 * 
		 * String excp = handler[0]; ObjectType theExp = null; try { theExp =
		 * (ObjectType) Type.getType(excp); } catch (Exception e) {
		 * jlog.info("catchall exception for " + positions[0] + " to "
		 * + positions[1] + ":" + e + ":" + excp); theExp = (ObjectType)
		 * Type.getType("Ljava/lang/Throwable;"); } jlog.info("hallo:"
		 * + theExp); InstructionHandle ih_start = ic.get(positions[0].trim());
		 * InstructionHandle ih_end = ic.get(positions[1].trim());
		 * jlog.info("2"); while ((ih_end.getNext() != null) &&
		 * !(ih_end.getNext().getInstruction() instanceof NOP)) { ih_end =
		 * ih_end.getNext(); } InstructionHandle ih_handler =
		 * ic.get(handler[1].trim()).getNext(); jlog.info(positions[0]
		 * + ":" + positions[1] + ":" + excp + ":" + handler[1]);
		 * jlog.info(ih_start + ":" + ih_end + ":" + excp + ":" +
		 * ih_handler); // jlog.info("pos1:"+positions[1]);
		 * 
		 * i_exp++;
		 * 
		 * mg.addExceptionHandler(ih_start, ih_end, ih_handler, theExp);
		 * jlog.info("1"); }
		 */

		// for (String x : ic.keySet()) {
		// jlog.info(x);
		// }
		// for (String z : alex) {
		// jlog.info(z);
		// }
		// if (i_exp > 0) {
		// Utils.stopAndDump("test exceptions");
		// }
		/*
		 * if (true) { InstructionList ilx = mg.getInstructionList();
		 * InstructionHandle idx = ilx.getStart(); while (idx.getNext() != null)
		 * { InstructionHandle idxnext = idx.getNext(); if (idx.getInstruction()
		 * instanceof NOP) { try { ilx.delete(idx); } catch (Exception e) { //
		 * Targeted do nothing } } idx = idxnext; } }
		 */

		// jlog.info(mg.getInstructionList().toString(true));
		jlog.info("nops removed");

		/*
		 * InstructionList ilx = mg.getInstructionList();
		 * jlog.info(ilx.toString()); InstructionHandle idx = ilx.getEnd();
		 * while (idx.getPrev() != null) { InstructionHandle idxprev =
		 * idx.getPrev(); if (idx.getInstruction() instanceof NOP) { try {
		 * ilx.delete(idx); } catch (Exception e) { // Targeted do nothing } }
		 * idx = idxprev; } jlog.info(ilx.toString());
		 * mg.setInstructionList(ilx);
		 */
		mg.update();
		InstructionList il1 = mg.getInstructionList();

		if (il1 != null) {
			il1.setPositions(true);

			InstructionHandle ih = il1.getEnd();

			while (ih.getInstruction() instanceof NOP) {
				InstructionHandle ig = ih;
				ih = ih.getPrev();
				try {
					if (!ih.hasTargeters())
						il.delete(ig);
				} catch (TargetLostException e) {
					jlog.info("CurHandle:"+ig);
					e.printStackTrace();
				}
				if (ih == null) {
					break;
				}
			}

			if (il1 != null)
				il1.setPositions(true);
		}
		// jlog.info(Arrays.toString(mg.getLineNumbers()));
		// LineNumberTable lnt = mg.getLineNumberTable(cpg);
		// for (int i = 0; i < lnt.getLength(); i++) {
		// jlog.info(lnt.getSourceLine(i)+lnt.);
		// }

		// il1 = mg.getInstructionList();

		jlog.info("nops removed! 1");

		mg.removeNOPs();

		// boolean end = false;
		doFixups(cpg, mg);

		mg.removeNOPs();

		il1.setPositions(true);

		jlog.info("nop removed! 2");

		// il1 = mg.getInstructionList();
		// ArrayList<String> pos = getArrayListUntilEndmarker(lr, "locals",
		// false);

		boolean processLineNumberTables = false; // unsupported , needs smart
		// remapping from old to new
		// instruction handles to
		// linenumbers

		if (processLineNumberTables) {
			ArrayList<String> pos = getArrayListUntilEndmarker(lr, "locals",
					false);
			for (String thepos : pos) {
				thepos = thepos.trim();
				String[] items = thepos.split(" ");
				// jlog.info("lnc="+Arrays.toString(items));
				items[0] = items[0].trim().replaceAll("0x", "");
				items[1] = items[1].trim().replaceAll("line=", "");
				jlog.info("lnc=" + Arrays.toString(items));
				// jlog.info(bl1.getByLogicalOffset(items[0]));
				// jlog.info(ic.getInstructions());
				// jlog.info(ic.keySet());
				// jlog.info(items[0]);
				InstructionHandle ih = ic.get(items[0]);
				// jlog.info("ih="+ih.getInstruction());
				LineNumberGen lnc = mg.addLineNumber(ih, Integer
						.parseInt(items[1]));
			}
		}
		jlog.info(mg.getName());
		jlog.info(mg.getSignature());
		jlog.info("" + locals);
		for (Iterator<String> e = locals.getlocals().keySet().iterator(); e
				.hasNext();) {
			String z = e.next();
			LocalVar lv = locals.getlocals().get(z);
			// jlog.info("lvname=" + lv.name);
			// jlog.info("s=" + il.getStart());
			// jlog.info("e=" + il.getEnd());

			if (lv.getName().equals("this")) {
				jlog.info("this  pointer skipped");
			} else {
				if (lv.getVarType() == VarType.TEMP && !lv.getType().equals("")) {
					jlog.info("type=" + lv.getType());
					LocalVariableGen lvg = mg.addLocalVariable(lv.getName(),
							Type.getType(lv.getType()), /* slot, */
							il.getStart(), il.getEnd());
					jlog.info("added lvg:" + lvg);
				}
			}
		}

		return mg;

	}

	private void doFixups(ConstantPoolGen cpg, MethodGen mg) {
		InstructionList il1 = mg.getInstructionList();
		InstructionHandle ih = il1.getStart();

		boolean end = false;
		while (!end) {
			InstructionHandle in = ih.getNext();
			if (in == null) {
				break;
			}

			if ((in.getTargeters() != null)) {

			} else {

				InstructionHandle io = in.getNext();

				// jlog.info(ih);
				// jlog.info(in);
				// if (ih.getInstruction() instanceof ISTORE &&
				// in.getInstruction() instanceof ILOAD)
				// Utils.stopAndDump("found!!!!!!!");

				if (ih.getInstruction() instanceof ALOAD
						&& in.getInstruction() instanceof ASTORE) {
					ALOAD ah = (ALOAD) ih.getInstruction();
					ASTORE an = (ASTORE) in.getInstruction();
					if (an.getIndex() == ah.getIndex()) {
						ih.setInstruction(new NOP());
						in.setInstruction(new NOP());
					}
				}
				
			
				/*if (ih.getInstruction() instanceof LDC
						&& in.getInstruction() instanceof ISTORE) {

				}*/

				if (ih.getInstruction() instanceof ILOAD
						&& in.getInstruction() instanceof ISTORE) {
					ILOAD ah = (ILOAD) ih.getInstruction();
					ISTORE an = (ISTORE) in.getInstruction();
					if (an.getIndex() == ah.getIndex()) {
						ih.setInstruction(new NOP());
						in.setInstruction(new NOP());
					}
				}

				if (ih.getInstruction() instanceof LDC2_W
						&& in.getInstruction() instanceof DSTORE
						&& io.getInstruction() instanceof LLOAD) {
					LDC2_W ah = (LDC2_W) ih.getInstruction();
					DSTORE dstore = (DSTORE) in.getInstruction();
					LLOAD lload = (LLOAD) io.getInstruction();
					if (dstore.getIndex() == lload.getIndex()) {
						int ref = ah.getIndex();
						Constant cd = cpg.getConstant(ref);
						ConstantDouble cdd = (ConstantDouble) cd;
						double d = cdd.getBytes();
						long l = Double.doubleToLongBits(d);
						int lref = cpg.addLong(l);
						ih.setInstruction(new LDC2_W(lref));
						in.setInstruction(new LSTORE(dstore.getIndex()));
						// Utils.stopAndDump("found!!!!!!!");
					}
				}

				if (io != null && io.getTargeters() == null) {

					if (ih.getInstruction() instanceof ISTORE
							&& in.getInstruction() instanceof ILOAD
							&& in.getNext().getInstruction() instanceof IRETURN) {
						ISTORE ah = (ISTORE) ih.getInstruction();
						ILOAD an = (ILOAD) in.getInstruction();
						if (an.getIndex() == ah.getIndex()) {
							ih.setInstruction(new NOP());
							in.setInstruction(new NOP());
							// Utils.stopAndDump("found!!!!!!!");
						}
					}

				}

				if (io != null) {
					InstructionHandle ip = io.getNext();

					if (ip!= null
							&& ih.getInstruction() instanceof ASTORE 
							&&in.getInstruction() instanceof ALOAD
							&& ip.getInstruction() instanceof ALOAD)
					{
						ASTORE astore1 = (ASTORE) ih.getInstruction();
						ALOAD aload1 = (ALOAD) in.getInstruction();
						ALOAD aload2 = (ALOAD) ip.getInstruction();
						
						if (astore1.getIndex() == aload1.getIndex() && 
							astore1.getIndex() == aload2.getIndex()) 
						{
							ih.setInstruction(new DUP());
							in.setInstruction(new NOP());
							ip.setInstruction(new NOP());
							jlog.info("DUPPER activated");
						}
							
					}
											
					
					
					
					if (ip != null
							&& ih.getInstruction() instanceof ACONST_NULL
							&& in.getInstruction() instanceof ASTORE
							&& io.getInstruction() instanceof ALOAD
							&& ip.getInstruction() instanceof ILOAD) {
						ASTORE astore = (ASTORE) in.getInstruction();
						ILOAD iload = (ILOAD) ip.getInstruction();
						// LLOAD lload = (LLOAD) io.getInstruction();
						if (astore.getIndex() == iload.getIndex()) {
							// int ref = astore.getIndex();
							// int lref = cpg.addInteger(0);
							ih.setInstruction(new ICONST(0));
							in.setInstruction(new ISTORE(astore.getIndex()));
							// Utils.stopAndDump("found!!!!!!!");
						}
					}

					if (ip != null && ih.getInstruction() instanceof LDC
							&& in.getInstruction() instanceof FSTORE
							&& io.getInstruction() instanceof ALOAD
							&& ip.getInstruction() instanceof ILOAD) {
						FSTORE fstore = (FSTORE) in.getInstruction();
						ILOAD iload = (ILOAD) ip.getInstruction();
						LDC ldc = (LDC) ih.getInstruction();
						// LLOAD lload = (LLOAD) io.getInstruction();
						if (fstore.getIndex() == iload.getIndex()) {
							int ref = ldc.getIndex();
							ConstantFloat f = (ConstantFloat) cpg
									.getConstant(ref);
							int inti = Float.floatToRawIntBits(f.getBytes());
							ih.setInstruction(new LDC(cpg.addInteger(inti)));
							in.setInstruction(new ISTORE(fstore.getIndex()));
							// Utils.stopAndDump("found!!!!!!!");
						}
					}

					if (ip != null && ih.getInstruction() instanceof ICONST
							&& in.getInstruction() instanceof ISTORE
							&& io.getInstruction() instanceof ILOAD
							&& ip.getInstruction() instanceof PUTSTATIC) {
						ICONST iconst = (ICONST) ih.getInstruction();
						PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();
						// LDC ldc = (LDC) ih.getInstruction();
						int val = iconst.getValue().intValue();
						// LLOAD lload = (LLOAD) io.getInstruction();
						Type typeto = ps.getFieldType(cpg);
						if (typeto.equals(Type.FLOAT)) {
							ih.setInstruction(new NOP());
							in.setInstruction(new NOP());
							io.setInstruction(new FCONST(Float
									.intBitsToFloat(val)));
						}
					}

					// 92: aconst_null
					// 93: astore_2
					// 94: iload_2
					// 95: anewarray #191; //class android/widget/Button

					if (ip != null
							&& ih.getInstruction() instanceof ACONST_NULL
							&& in.getInstruction() instanceof ASTORE
							&& io.getInstruction() instanceof ILOAD
							&& ip.getInstruction() instanceof ANEWARRAY) {
						ASTORE astore = (ASTORE) in.getInstruction();
						ILOAD iload = (ILOAD) io.getInstruction();
						// PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();

						if (astore.getIndex() == iload.getIndex()) {
							ih.setInstruction(new ICONST(0));
							in.setInstruction(new ISTORE(astore.getIndex()));
							// in.setInstruction(new NOP());
							// io.setInstruction(new ICONST(0));
						}
					}

					// 732: aconst_null
					// 733: astore_2
					// 734: fload_1
					// 735: fload_2
					// 736: fcmpl

					if (ip != null
							&& ih.getInstruction() instanceof ACONST_NULL
							&& in.getInstruction() instanceof ASTORE
							&& io.getInstruction() instanceof FLOAD
							&& ip.getInstruction() instanceof FLOAD) {
						InstructionHandle iq = ip.getNext();
						if (iq.getInstruction() instanceof FCMPL) {

							ASTORE astore = (ASTORE) in.getInstruction();
							FLOAD fload1 = (FLOAD) io.getInstruction();
							FLOAD fload2 = (FLOAD) ip.getInstruction();
							// PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();

							if (astore.getIndex() == fload1.getIndex()
									|| astore.getIndex() == fload2.getIndex()) {
								ih.setInstruction(new FCONST(0));
								in
										.setInstruction(new FSTORE(astore
												.getIndex()));
								// in.setInstruction(new NOP());
								// io.setInstruction(new ICONST(0));
							}
						}

					}
					// 106: aconst_null
					// 107: astore_2
					// 108: iload_1
					// 109: iload_2
					// 110: if_icmplt 1377

					if (ip != null
							&& ih.getInstruction() instanceof ACONST_NULL
							&& in.getInstruction() instanceof ASTORE
							&& io.getInstruction() instanceof ILOAD
							&& ip.getInstruction() instanceof ILOAD) {
						InstructionHandle iq = ip.getNext();
						if (iq.getInstruction() instanceof IF_ICMPLT) {

							ASTORE astore = (ASTORE) in.getInstruction();
							ILOAD iload1 = (ILOAD) io.getInstruction();
							ILOAD iload2 = (ILOAD) ip.getInstruction();
							// PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();

							if (astore.getIndex() == iload1.getIndex()
									|| astore.getIndex() == iload2.getIndex()) {
								ih.setInstruction(new ICONST(0));
								in
										.setInstruction(new ISTORE(astore
												.getIndex()));
								// in.setInstruction(new NOP());
								// io.setInstruction(new ICONST(0));
							}
						}

					}

					// 83: ldc2_w #64; //double 3.03554E-318d
					// 86: dstore 12
					// 88: aload 11
					// 90: lload 12

					if (ip != null && ih.getInstruction() instanceof LDC2_W
							&& in.getInstruction() instanceof DSTORE
							&& io.getInstruction() instanceof ALOAD
							&& ip.getInstruction() instanceof LLOAD) {

						LDC2_W ldc = (LDC2_W) ih.getInstruction();

						DSTORE dstore = (DSTORE) in.getInstruction();
						// ILOAD iload1 = (ILOAD) io.getInstruction();
						LLOAD iload = (LLOAD) ip.getInstruction();
						// PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();

						if (dstore.getIndex() == iload.getIndex()) {
							ConstantDouble cd = (ConstantDouble) cpg
									.getConstant(ldc.getIndex());

							ih.setInstruction(new LDC2_W(cpg.addLong(Double
									.doubleToRawLongBits(cd.getBytes()))));
							in.setInstruction(new LSTORE(dstore.getIndex()));
							// in.setInstruction(new NOP());
							// io.setInstruction(new ICONST(0));
						}

					}

					if (ih.getInstruction() instanceof ICONST
							&& in.getInstruction() instanceof ISTORE) {

						// ACONST_NULL aconst = (ACONST_NULL)
						// ih.getInstruction();
						ISTORE istore = (ISTORE) in.getInstruction();
						ICONST iconst = (ICONST) ih.getInstruction();
						int reg = istore.getIndex();
						InstructionHandle lauf = in.getNext();

						int val = (Integer) iconst.getValue();

						if (val == 0) {

							boolean ende = false;
							while (!ende) {

								if (lauf.getInstruction() instanceof ILOAD) {
									ILOAD iload2 = (ILOAD) lauf
											.getInstruction();
									int thereg2 = iload2.getIndex();
									if (reg == thereg2) {
										ende = true;
										break;
									}
								} else

								if (lauf.getInstruction() instanceof ALOAD) {
									ALOAD aload2 = (ALOAD) lauf
											.getInstruction();
									int thereg2 = aload2.getIndex();
									if (reg == thereg2) {
										ih.setInstruction(new ACONST_NULL());
										in.setInstruction(new ASTORE(thereg2));
										break;
									}
								} else

								if (lauf.getInstruction() instanceof FLOAD) {
									FLOAD fload2 = (FLOAD) lauf
											.getInstruction();
									int thereg2 = fload2.getIndex();
									if (reg == thereg2) {
										ih.setInstruction(new FCONST(0));
										in.setInstruction(new FSTORE(thereg2));
										break;
									}
								}

								lauf = lauf.getNext();
								if (lauf == null) {
									ende = true;
								}
							}
						}
					}

					if (ih.getInstruction() instanceof ACONST_NULL
							&& in.getInstruction() instanceof ASTORE) {

						// ACONST_NULL aconst = (ACONST_NULL)
						// ih.getInstruction();
						ASTORE astore = (ASTORE) in.getInstruction();
						int reg = astore.getIndex();
						InstructionHandle lauf = in.getNext();

						boolean ende = false;
						while (!ende) {

							if (lauf.getInstruction() instanceof ALOAD) {
								ALOAD aload2 = (ALOAD) lauf.getInstruction();
								int thereg2 = aload2.getIndex();
								if (reg == thereg2) {
									ende = true;
									break;
								}
							} else

							if (lauf.getInstruction() instanceof ILOAD) {
								ILOAD iload2 = (ILOAD) lauf.getInstruction();
								int thereg2 = iload2.getIndex();
								if (reg == thereg2) {
									ih.setInstruction(new ICONST(0));
									in.setInstruction(new ISTORE(thereg2));
									break;
								}
							} else

							if (lauf.getInstruction() instanceof FLOAD) {
								FLOAD fload2 = (FLOAD) lauf.getInstruction();
								int thereg2 = fload2.getIndex();
								if (reg == thereg2) {
									ih.setInstruction(new FCONST(0));
									in.setInstruction(new FSTORE(thereg2));
									break;
								}
							}

							lauf = lauf.getNext();
							if (lauf == null) {
								ende = true;
							}
						}
					}

					/*
					 * if (ip != null) { InstructionHandle iq = ip.getNext(); if
					 * (iq != null && in.getInstruction() instanceof ASTORE &&
					 * io.getInstruction() instanceof ILOAD &&
					 * ip.getInstruction() instanceof ILOAD
					 * 
					 * && iq.getInstruction() instanceof IF_ICMPLT) {
					 * 
					 * ASTORE astore = (ASTORE) in.getInstruction(); ILOAD
					 * iload1 = (ILOAD) io.getInstruction(); ILOAD iload2 =
					 * (ILOAD) ip.getInstruction(); // PUTSTATIC ps =
					 * (PUTSTATIC) ip.getInstruction();
					 * 
					 * if (astore.getIndex() == iload1.getIndex() ||
					 * astore.getIndex() == iload2.getIndex()) {
					 * ih.setInstruction(new ICONST(0)); in .setInstruction(new
					 * ISTORE(astore .getIndex())); // in.setInstruction(new
					 * NOP()); // io.setInstruction(new ICONST(0)); } } }
					 */

					if (ip != null) {
						InstructionHandle iq = ip.getNext();
						if (iq != null
								&& ih.getInstruction() instanceof GETSTATIC
								&& in.getInstruction() instanceof ASTORE
								&& io.getInstruction() instanceof ILOAD
								&& ip.getInstruction() instanceof ILOAD
								&& iq.getInstruction() instanceof IF_ICMPEQ) {

							// GETSTATIC gstatic = (GETSTATIC)
							// ih.getInstruction();
							ASTORE astore = (ASTORE) in.getInstruction();
							ILOAD iload1 = (ILOAD) io.getInstruction();
							ILOAD iload2 = (ILOAD) ip.getInstruction();
							IF_ICMPEQ ifinstr = (IF_ICMPEQ) iq.getInstruction();
							// PUTSTATIC ps = (PUTSTATIC) ip.getInstruction();

							if (astore.getIndex() == iload2.getIndex()
									|| astore.getIndex() == iload1.getIndex()) {
								io.setInstruction(new ALOAD(iload1.getIndex()));
								ip.setInstruction(new ALOAD(iload2.getIndex()));
								iq.setInstruction(new IF_ACMPEQ(ifinstr
										.getTarget()));
								// in
								// .setInstruction(new ISTORE(astore
								// .getIndex()));
								// in.setInstruction(new NOP());
								// io.setInstruction(new ICONST(0));
							}
						}
					}

				}

			}
			ih = in;

		}
	}

	private static ArrayList<String> getArrayListUntilEndmarker(
			BufferedReader lr, String endmarker, boolean withend) {
		ArrayList<String> al = new ArrayList<String>();
		String zline = "";

		try {
			boolean loop = true;
			while (loop) {
				zline = getNextTrimmedLine(lr);
				if (zline == null)
					break;
				if (zline.startsWith(endmarker)) {
					break;
				}
				// !().startsWith(endmarker)
				// && zline.length() > 0
				// && zline != null

				if (zline.length() > 0) {
					al.add(zline);
					// jlog.info("read (" + endmarker + "):" + zline);
				}
			}
		} catch (IOException e) {
			// e.printStackTrace();
			// System.exit(1);
		}
		if (withend) {
			al.add(zline);
		}
		return al;
	}

	private static String getNextTrimmedLine(BufferedReader lr)
			throws IOException {
		String z = lr.readLine();
		if (z != null) {
			z = z.trim();

			if (z.startsWith("source_file_idx")) {
				// new Throwable().printStackTrace();

			}
		}
		// jlog.info("x:" + z);

		return z; // == null ? "" : z;
	}

	private InstructionList doOpcodes(MethodGen mg,
			InstructionList bisher,
			DalvikCodeLine dcl,

			// String[] regs,
			// String[] ops, String offsetandcode[], String relativeandmne[],
			OpcodeSequence bl1, ConstantPoolGen cpg, InstructionCache ic,
			LocalVarContext locals) {
		// jlog.info(locals);
		// InstructionList iold = ic.getIntructions();
		InstructionList il = new InstructionList();
		String z_il = il.toString(true);
		String[] ops = dcl.getOps();
		String[] regs = dcl.getRegs();
		String[] offsetandcode = dcl.getoffset();
		String[] relativeandmne = dcl.getrela();
		String[] comps = offsetandcode[1].split(" ");
		jlog.info("comps=" + Arrays.toString(comps));

		String opname = ops[0];
		// String currentInstr = relativeandmne[0];
		if (opname.equals("const/4")) {
			handle_const4(dcl, cpg, locals, il, ops);
		} else if (opname.equals("iput")) {
			handle_iput(ops, il, cpg, locals);
		}

		// else if (opname.equals("iput-wide")) {
		// handle_iput(ops, il, cpg, locals);
		// }

		else if (opname.equals("iput-wide")) {
			handle_iput_wide(ops, il, cpg, locals);
		}

		else if (opname.equals("iget")) {
			handle_iget(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-wide")) {
			handle_iget_wide(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-boolean")) {
			handle_iget_boolean(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-short")) {
			handle_iget_short(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-byte")) {
			handle_iget_byte(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-char")) {
			handle_iget_char(ops, il, cpg, locals);
		}

		else if (opname.equals("iget-object")) {
			handle_iget_object(ops, il, cpg, locals);
		}

		else if (opname.equals("+iget-object-quick")) {
			OpCodeHandler_ODEX.handle_iget_object_quick(ops, il, cpg, locals);
		}

		else if (opname.equals("move-result-object")) {
			handle_move_result_object(ops, il, cpg, locals);
		}

		else if (opname.equals("move-result")) {
			handle_move_result(ops, il, cpg, locals, bl1, dcl);
		}

		else if (opname.equals("move-result-wide")) {
			handle_move_result_wide(ops, il, cpg, locals, bl1, dcl);
		}

		else if (opname.equals("move-exception")) {
			handle_move_exception(ops, il, cpg, locals);
		}

		else if (opname.equals("throw")) {
			handle_throw_exception(ops, il, cpg, locals);
		}

		else if (opname.equals("new-array")) {
			handle_new_array(ops, il, cpg, locals);
		}
		
		else if (opname.equals("new-instance")) {
			handle_new_instance(ops, il, cpg, locals);
		}

		else if (opname.equals("monitor-enter")) {
			String regfrom = ops[1].replaceAll(",", "");
			System.out.printf("monitorenter %s\n", regfrom);
			int themonitor = locals.didx2jvmidxstr(regfrom);
			il.append(new ALOAD(themonitor));
			il.append(new MONITORENTER());
		}

		else if (opname.equals("monitor-exit")) {
			String regfrom = ops[1].replaceAll(",", "");
			System.out.printf("monitorexit %s\n", regfrom);
			int themonitor = locals.didx2jvmidxstr(regfrom);
			il.append(new ALOAD(themonitor));
			il.append(new MONITOREXIT());
		}

		else if (opname.equals("if-eqz")) {

			// checklastTypeForRegister(dlc,regfrom);

			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");
			int reg = (locals.didx2jvmidxstr(regfrom));
			InstructionHandle ih = ic.get(toaddr);

			InstructionHandle iend = bisher.getEnd();

			String type = "";
			// jlog.info("Instruction:"+iend);

			while (iend != null) {
				Instruction i = iend.getInstruction();
				// jlog.info("Instruction:"+i);
				if (i instanceof ASTORE) {
					ASTORE as = (ASTORE) i;
					if (as.getIndex() == reg) {
						type = "object";
						break;
					}
				}

				if (i instanceof ISTORE) {
					ISTORE as = (ISTORE) i;
					if (as.getIndex() == reg) {
						type = "";
						break;
					}

				}
				iend = iend.getPrev();
			}
			// Utils.stopAndDump("ende:"+type);

			if (type.equals("object")) {
				il.append(new ALOAD(reg));
				il.append(new IFNULL(ih));

			} else {
				System.out.printf("if %s == 0 goto %s; \n", regfrom, toaddr);
				il.append(new ILOAD(reg));
				// il.append(new SIPUSH((short) 0));
				il.append(new IFEQ(ih));
				// jlog.info(toaddr);

			}
		}

		else if (opname.equals("if-nez")) {

			// checklastTypeForRegister(dlc,regfrom);

			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");
			int reg = (locals.didx2jvmidxstr(regfrom));
			InstructionHandle ih = ic.get(toaddr);
			String t = locals.getLV(regfrom).getType();
			// jlog.info(t);
			// Utils.stopAndDump("t:"+t+" "+regfrom+":"+locals.getLV(regfrom));
			InstructionHandle iend = bisher.getEnd();

			String type = "";
			// jlog.info("Instruction:"+iend);

			while (iend != null) {
				Instruction i = iend.getInstruction();
				// jlog.info("Instruction:"+i);

				if (i instanceof ISTORE) {
					ISTORE as = (ISTORE) i;
					if (as.getIndex() == reg) {
						type = "";
						break;
					}

				}
				
				else if (i instanceof ASTORE) {
					ASTORE as = (ASTORE) i;
					if (as.getIndex() == reg) {
						type = "object";
						break;
					}
				}
				
				else if (i instanceof ALOAD) {
					ALOAD as = (ALOAD) i;
					if (as.getIndex() == reg) {
						type = "object";
						break;
					}
				}

				iend = iend.getPrev();
			}
			// Utils.stopAndDump("ende:"+type);

			if (type.equals("object")) {
				il.append(new ALOAD(reg));
				il.append(new IFNONNULL(ih));

			} 
			
			else {
				System.out.printf("if %s == 0 goto %s; \n", regfrom, toaddr);
				il.append(new ILOAD(reg));
				// il.append(new SIPUSH((short) 0));
				il.append(new IFNE(ih));
				// jlog.info(toaddr);

			}
		}

		else if (opname.equals("if-gez")) {
			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");

			System.out.printf("if %s >= 0 goto %s; \n", regfrom, toaddr);
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			// il.append(new SIPUSH((short) 0));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IFGE(ih));
			// jlog.info(toaddr);
		}

		else if (opname.equals("if-gtz")) {
			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");

			System.out.printf("if %s >= 0 goto %s; \n", regfrom, toaddr);
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			// il.append(new SIPUSH((short) 0));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IFGT(ih));
			// jlog.info(toaddr);
		}

		else if (opname.equals("if-ltz")) {
			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");

			System.out.printf("if %s >= 0 goto %s; \n", regfrom, toaddr);
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			// il.append(new SIPUSH((short) 0));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IFLT(ih));
			// jlog.info(toaddr);
		}

		else if (opname.equals("if-lez")) {
			String regfrom = ops[1].replaceAll(",", "");
			String toaddr = ops[2].replaceAll(",", "");

			System.out.printf("if %s <= 0 goto %s; \n", regfrom, toaddr);
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			// il.append(new SIPUSH((short) 0));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IFLE(ih));
			jlog.info(toaddr);
		} else if (opname.equals("if-ne")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String toaddr = ops[3].replaceAll(",", "");
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			// il.append(ILOAD((short) 0));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPNE(ih));
			jlog.info(toaddr);

			System.out.printf("if %s != %s  goto %s; \n", regfrom, regto,
					toaddr);

		}

		else if (opname.equals("if-eq")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String toaddr = ops[3].replaceAll(",", "");
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPEQ(ih));
			jlog.log(Level.INFO, "if %s != %s  goto %s; \n", new Object[] {
					regfrom, regto, toaddr });

		}

		else if (opname.equals("if-ge")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");
			String toaddr = ops[3].replaceAll(",", "");

			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPGE(ih));

			jlog.log(Level.INFO, "if %s >= %s  goto %s; \n", new Object[] {
					regfrom, regto, toaddr });

		}

		else if (opname.equals("if-le")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String toaddr = ops[3].replaceAll(",", "");
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPLE(ih));

			System.out.printf("if %s <= %s  goto %s; \n", regfrom, regto,
					toaddr);

		}

		// else if (opname.equals("if-lez")) {
		// String regfrom = ops[1].replaceAll(",", "");
		//
		// String toaddr = ops[2].replaceAll(",", "");
		// il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
		// il.append(new SIPUSH((short) 0));
		// // il.append(ILOAD((short) 0));
		// InstructionHandle ih = ic.get(toaddr);
		// il.append(new IFLE(ih));
		// jlog.info(toaddr);
		//
		// System.out.printf("if %s <= 0  goto %s; \n", regfrom, toaddr);
		//
		// }

		// else if (opname.equals("if-ltz")) {
		// String regfrom = ops[1].replaceAll(",", "");
		//
		// String toaddr = ops[2].replaceAll(",", "");
		// il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
		// il.append(new SIPUSH((short) 0));
		// // il.append(ILOAD((short) 0));
		// InstructionHandle ih = ic.get(toaddr);
		// il.append(new IFLT(ih));
		// jlog.info(toaddr);
		//
		// System.out.printf("if %s <= 0  goto %s; \n", regfrom, toaddr);
		//
		// }

		else if (opname.equals("if-gt")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String toaddr = ops[3].replaceAll(",", "");
			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPGT(ih));
			// jlog.info(toaddr);

			System.out
					.printf("if %s > %s  goto %s; \n", regfrom, regto, toaddr);

		} else if (opname.equals("if-lt")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String toaddr = ops[3].replaceAll(",", "");

			il.append(new ILOAD((locals.didx2jvmidxstr(regfrom))));
			il.append(new ILOAD((locals.didx2jvmidxstr(regto))));
			InstructionHandle ih = ic.get(toaddr);
			il.append(new IF_ICMPLT(ih));
			// jlog.info(toaddr);

			System.out
					.printf("if %s < %s  goto %s; \n", regfrom, regto, toaddr);

		}

		/*
		 * else if (opname.equals("if-nez")) { String regfrom =
		 * ops[1].replaceAll(",", ""); String toaddr = ops[2].replaceAll(",",
		 * ""); InstructionHandle ih = ic.get(toaddr); il.append(new
		 * ILOAD((locals.didx2jvmidxstr(regfrom)))); il.append(new IFNE(ih));
		 * jlog.info(toaddr);
		 * 
		 * System.out.printf("if %s != 0 goto %s; \n", regfrom, toaddr);
		 * 
		 * }
		 */

		else if (opname.equals("goto")) {
			String toaddr = ops[1].replaceAll(",", "");
			InstructionHandle ih = ic.get(toaddr);
			il.append(new GOTO(ih));
			// jlog.info(toaddr);

			System.out.printf("goto %s ; \n", ih);

		} else if (opname.equals("goto/16")) {
			String regfrom = ops[1].replaceAll(",", "");

			jlog.info("addr1=" + offsetandcode[0]);
			jlog.info("addr2=" + offsetandcode[1]);
			int pos = dcl.getPos();
			// int pos = Integer.parseInt(relativeandmne[0], 16);
			String str_offset = offsetandcode[1].split(" ")[1];
			jlog.info(str_offset);
			int high = Integer.parseInt(str_offset.substring(2, 4), 16);
			int low = Integer.parseInt(str_offset.substring(0, 2), 16);
			// jlog.info(high);
			// jlog.info(low);

			int offset = -65536 + high * 256 + low;
			int destaddr = pos + offset;
			String str_dest = Utils.getFourCharHexString(destaddr);
			// jlog.info(offset);
			System.out.printf("goto/16 %s (%s => %s); \n", regfrom, offset,
					str_dest);
			// System.out.printf("goto/16 %s (%s); \n", regfrom, offset);
			InstructionHandle ih = ic.get(str_dest);
			il.append(new GOTO(ih));

			// System.exit(0);

		}

		else if (opname.equals("nop")) {
			il.append(new NOP());
			System.out.printf("nop; \n");

		}

		// else if (opname.equals("if-gtz")) {
		// String regfrom = ops[1].replaceAll(",", "");
		//
		// String toaddr = ops[3].replaceAll(",", "");
		//
		// System.out.printf("if %s >0  goto %s; \n", regfrom, toaddr);
		//
		// }

		else if (opname.equals("const")) { // float ist quatsch take int
			String regto = ops[1].replaceAll(",", "");
			String val = ops[ops.length - 1].replaceAll(",", "").substring(1)
					.toUpperCase();

			System.out.printf("%s = (int) %s  \n", regto, val);
			int ival = (int) Long.parseLong(val, 16);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger((int) Long.parseLong(val, 16))));
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("iput-object")) {
			handle_iput_object(ops, il, cpg, locals);
		}

		else if (opname.equals("const/high16_old")) {

			// int theval = Utils.swapInt(Integer.parseInt(comps[1], 16)) *
			// 65536;
			String regto = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			int intval = Integer.parseInt(val);
			// il.append(new ICONST(intval << 16));
			getShortestIntegerPush(cpg, intval, il);
			// il.append(new ICONST(intval << 16));
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
			System.out.printf("high16(%s) = (%s) %s;\n", regto, type, val);

		}

		else if (opname.equals("const/high16")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			String valhex = ops[5].replaceAll(",", "").trim();

			System.out.printf("float %s = (%s) %s; // %s*\n", regfrom, type,
					val, valhex);
			Float m = 0.0f;
			if (val.equals("nan")) {
				m = Float.NaN;
			} else {
				Float m1 = Float.valueOf(val);
				jlog.info(valhex);
				if (valhex.length() < 5) {
					valhex = "#" + "0000".substring(0, 5 - valhex.length())
							+ valhex.substring(1);
				}
				jlog.info(valhex);
				String z = valhex.substring(1, 3);
				String y = valhex.substring(3);
				int l1 = Integer.parseInt(z, 16) << 12;
				int l2 = Integer.parseInt(y, 16);
				l1 = l1 + l2;
				m = Float.intBitsToFloat(l1);
				jlog.info(valhex + "0000" + ":" + m + ":" + m1 + ":"
						+ y + ":" + z);
				jlog.info(Integer.toString(Float
						.floatToRawIntBits(0.2f), 16));
				jlog.info(Integer.toString(l1, 16));
				// Utils.stopAndDump("Hello");
			}
			il.append(new LDC(cpg.addFloat(m)));

			il.append(new FSTORE(locals.didx2jvmidxstr(regfrom)));

			// System.exit(0);
		}

		else if (opname.equals("const-wide")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			String valhex = ops[5].replaceAll(",", "");

			System.out.printf("double %s = (%s) %s; // %s\n", regfrom, type,
					val, valhex);
			Double m = 0.0d;
			if (val.equals("nan")) {
				m = Double.NaN;
			} else {
				Double m1 = Double.valueOf(val);
				String z = valhex.substring(1, 14);
				String y = valhex.substring(14);
				long l1 = Long.parseLong(z, 16) << 12;
				long l2 = Long.parseLong(y, 16);
				l1 = l1 + l2;
				m = Double.longBitsToDouble(l1);
				jlog.info(valhex + "0000" + ":" + m + ":" + m1 + ":"
						+ y + ":" + z);
				jlog.info(Long.toString(Double
						.doubleToRawLongBits(0.2), 16));
				jlog.info(Long.toString(l1, 16));
				// Utils.stopAndDump("Hello");
			}
			il.append(new LDC2_W(cpg.addDouble(m)));

			il.append(new DSTORE(locals.didx2jvmidxstr(regfrom)));

			// System.exit(0);
		}

		else if (opname.equals("const-class")) {
			String regto = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			// String val = ops[3].replaceAll(",", "");
			String valhex = ops[4].replaceAll(",", "");

			System.out.printf("Class %s = (Class) %s; // %s\n", regto, type,
					valhex);

			// il.append(new
			// LDC_W(cpg.addClass(toJavaName(type.substring(1)))));
			// int reg= locals.didx2jvmidxstr(regto);
			// il.append(m_currentInstructionFactory.createConstant(arg0))
			// il.append(m_currentInstructionFactory.createLoad(new
			// ObjectType(type),reg));

			// String origtype = type;
			type = type.trim();

			// if (!type.startsWith("[")) {
			// if (type.startsWith("L")) {
			// type = type.substring(1);
			// if (type.endsWith(";")) {
			// type = type.substring(0, type.length() - 1);
			// }
			// }
			// }
			int classref = Utils.doAddClass(cpg, type);
			// ConstantClass cc = (ConstantClass) cpg.getConstant(classref);

			// il.append(new ACONST_NULL());
			// il.append(new ASTORE(locals.didx2jvmidxstr(regto)));
			il.append(new LDC(classref));
			// Utils.stopAndDump(type+":"+origtype+":"+toVMname(origtype));
			il.append(new ASTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("const-wide/16")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			String valhex = ops[5].replaceAll(",", "");

			System.out.printf("double %s = (%s) %s; // %s\n", regfrom, type,
					val, valhex);

			// System.exit(0);
			long l = Long.parseLong((valhex).substring(1), 16) << 12;
			Double m = Double.longBitsToDouble(l);
			jlog.info(valhex + "00000000000");
			jlog.info("theLong:"+l);
			jlog.info("theDouble:"+m);
			il.append(new LDC2_W(cpg.addDouble(m)));
			il.append(new DSTORE(locals.didx2jvmidxstr(regfrom)));

			// System.exit(0);
		}

		else if (opname.equals("const-wide/32")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			String valhex = ops[5].replaceAll(",", "");

			System.out.printf("double %s = (%s) %s; // %s\n", regfrom, type,
					val, valhex);

			// System.exit(0);
			long l = Long.parseLong((valhex).substring(1), 16) << 8;
			Double m = Double.longBitsToDouble(l);
			jlog.info(valhex + "0000000");
			jlog.info("theLong:"+l);
			jlog.info("theDouble:"+m);
			il.append(new LDC2_W(cpg.addDouble(m)));
			il.append(new DSTORE(locals.didx2jvmidxstr(regfrom)));

			// System.exit(0);
		}

		else if (opname.equals("const-wide/high16")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String val = ops[3].replaceAll(",", "");
			String valhex = ops[5].replaceAll(",", "");
			jlog.info(valhex);
			// System.exit(1);
			jlog.info("*val*");
			Double m1 = Double.valueOf(val);
			// String z = valhex.substring(1, 14);
			// String y = valhex.substring(14);
			// long l1 = Long.parseLong(z, 16) << 12;
			// long l2 = Long.parseLong(y, 16);
			// l1 = l1 + l2;

			String valhexzero = valhex.substring(1, 5);
			jlog.info(valhexzero);
			jlog.info("Shifted:"+(Long.parseLong(valhexzero, 16) << 48));
			jlog.info("Hex:"+Long
					.toHexString(Long.parseLong(valhexzero, 16) << 48));
			jlog.info(Long.toHexString(Double.doubleToLongBits(2.0d)));
			double doubleval = Double.longBitsToDouble(Long.parseLong(
					valhexzero, 16) << 48);

			// System.exit(1);

			// long intval = Long.parseLong(valhexzero, 16) << 12;
			// jlog.info(intval);

			// System.exit(1);

			// double floatval = Double.longBitsToDouble(val);
			// System.out.printf("high16(%s) = (%s) %s %s %s;\n", regfrom, type,
			// val, valhex, floatval);
			il.append(new LDC2_W(cpg.addDouble(doubleval)));
			il.append(new DSTORE(locals.didx2jvmidxstr(regfrom)));
			// Utils.stopAndDump("hier");
			// System.exit(1);
		} else if (opname.equals("sget-object")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new GETSTATIC(thefield));
			il.append(new ASTORE(thereg));

		} else if (opname.equals("sput")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ILOAD(thereg));
			il.append(new PUTSTATIC(thefield));
		} else if (opname.equals("sput-wide")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ILOAD(thereg));
			il.append(new PUTSTATIC(thefield));
		} else if (opname.equals("sget")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			Type t = getTypeForField(cpg, field);
			il.append(new GETSTATIC(thefield));
			// Field f = cpg.getMemberRef(thefield);

			if (t == Type.INT) {
				il.append(new ISTORE(thereg));
			} else if (t == Type.FLOAT) {
				il.append(new FSTORE(thereg));
			} else {
				Utils.stopAndDump("sgsdfgsdfg:" + t);
			}
			// System.exit(1);
		} else if (opname.equals("sget-wide")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			Type t = getTypeForField(cpg, field);
			il.append(new GETSTATIC(thefield));
			// Field f = cpg.getMemberRef(thefield);

			if (t == Type.LONG) {
				il.append(new LSTORE(thereg));
			} else if (t == Type.DOUBLE) {
				il.append(new DSTORE(thereg));
			} else {
				Utils.stopAndDump("sgsdfgsdfg:" + t);
			}
			// System.exit(1);

		} else if (opname.equals("sput-boolean")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ILOAD(thereg));
			il.append(new PUTSTATIC(thefield));
			System.out.printf("boolean %s = (boolean) %s;\n", field, regfrom);
			
		} else if (opname.equals("sput-char")) {
			// puts char value in "vx" into static field
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			// iload loads thereg onto the stack
			// "push"
			il.append(new ILOAD(thereg));
			// putstatic stores the static value on top of the statck to thefield
			il.append(new PUTSTATIC(thefield));
			System.out.printf("char %s = (char) %s;\n", field, regfrom);

		} else if (opname.equals("sget-boolean")) {
			// reads the boolean static field into "vx" (dalvik)
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("boolean %s = (boolean)%s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			// getstatic loads the static value in thefield onto the stack
			il.append(new GETSTATIC(thefield));
			// istore loads the top of the stack to thereg
			// "pop"
			il.append(new ISTORE(thereg));

		} else if (opname.equals("sget-char")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("char %s = (char)%s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new GETSTATIC(thefield));
			il.append(new ISTORE(thereg));
							
		} else if (opname.equals("sput-object")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ALOAD(thereg));
			il.append(new PUTSTATIC(thefield));
			System.out.printf("object %s = (object) %s;\n", field, regfrom);

		} else if (opname.equals("filled-new-array")) {
			String type = ops[2].replaceAll(",", "");
			String z = getstaticparams(regs);
			il.append(new SIPUSH((short) regs.length));

			String theType = type.substring(1);
			if (theType.startsWith("L")) {
				il.append(new ANEWARRAY(Utils.doAddClass(cpg, theType)));
			} else {
				il.append(new NEWARRAY((BasicType) Type.getType(theType)));
			}

			for (int i = 0; i < regs.length; i++) {
				il.append(new DUP());
				il.append(new SIPUSH((short) i));
				if (theType.startsWith("L")) {
					il.append(new ALOAD(locals.didx2jvmidxstr(regs[i])));
					il.append(new AASTORE());

				} else {
					il.append(new ILOAD(locals.didx2jvmidxstr(regs[i])));
					il.append(new IASTORE());
				}
			}

			System.out.printf("Object[] res   = new %s {%s} ;\n", type, z);

		}

		else if (opname.equals("cmpl-double")) {
			String to = ops[1].replaceAll(",", "");
			// System.out.printf("to"+to);

			String op1 = ops[2].replaceAll(",", "");
			// System.out.printf("op1"+op1);
			// System.exit(1);
			String op2 = ops[3].replaceAll(",", "");
			// System.exit(1);
			// String z =getparams(regs);
			System.out.printf("int %s = ((double)%s == (double) %s) ;\n", to,
					op1, op2);
			il.append(new DLOAD(locals.didx2jvmidxstr(op1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(op2)));
			il.append(new DCMPL());
			il.append(new ISTORE(locals.didx2jvmidxstr(to)));
			// System.exit(1);

		}

		else if (opname.equals("cmpl-float")) {
			String to = ops[1].replaceAll(",", "");
			// System.out.printf("to"+to);

			String op1 = ops[2].replaceAll(",", "");
			// System.out.printf("op1"+op1);
			// System.exit(1);
			String op2 = ops[3].replaceAll(",", "");
			// System.exit(1);
			// String z =getparams(regs);
			System.out.printf("int %s = ((float)%s == (float) %s) ;\n", to,
					op1, op2);
			il.append(new FLOAD(locals.didx2jvmidxstr(op1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(op2)));
			il.append(new FCMPL());
			il.append(new ISTORE(locals.didx2jvmidxstr(to)));
			// System.exit(1);

		} else if (opname.equals("cmpg-float")) {
			String to = ops[1].replaceAll(",", "");
			// System.out.printf("to"+to);

			String op1 = ops[2].replaceAll(",", "");
			// System.out.printf("op1"+op1);
			// System.exit(1);
			String op2 = ops[3].replaceAll(",", "");
			// System.exit(1);
			// String z =getparams(regs);
			System.out.printf("int %s = ((float)%s == (float) %s) ;\n", to,
					op1, op2);
			il.append(new FLOAD(locals.didx2jvmidxstr(op1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(op2)));
			il.append(new FCMPG());
			il.append(new ISTORE(locals.didx2jvmidxstr(to)));
			// System.exit(1);

		}

		else if (opname.equals("cmpg-double")) {
			String to = ops[1].replaceAll(",", "");
			// System.out.printf("to"+to);

			String op1 = ops[2].replaceAll(",", "");
			// System.out.printf("op1"+op1);
			// System.exit(1);
			String op2 = ops[3].replaceAll(",", "");
			// System.exit(1);
			// String z =getparams(regs);
			System.out.printf("int %s = ((float)%s == (float) %s) ;\n", to,
					op1, op2);
			il.append(new DLOAD(locals.didx2jvmidxstr(op1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(op2)));
			il.append(new DCMPG());
			il.append(new ISTORE(locals.didx2jvmidxstr(to)));
			// System.exit(1);

		}

		else if (opname.equals("cmp-long")) {
			String to = ops[1].replaceAll(",", "");
			// System.out.printf("to"+to);

			String op1 = ops[2].replaceAll(",", "");
			// System.out.printf("op1"+op1);
			// System.exit(1);
			String op2 = ops[3].replaceAll(",", "");
			// System.exit(1);
			// String z =getparams(regs);
			System.out.printf("int %s = ((long) %s == (long)%s) ;\n", to, op1,
					op2);
			il.append(new LLOAD(locals.didx2jvmidxstr(op1)));
			il.append(new LLOAD(locals.didx2jvmidxstr(op2)));
			il.append(new LCMP());
			il.append(new ISTORE(locals.didx2jvmidxstr(to)));
			// System.exit(1);

		}

		// else if (opname.equals("cmpl-float")) {
		// String to = ops[1].replaceAll(",", "");
		// // System.out.printf("to"+to);
		//
		// String op1 = ops[2].replaceAll(",", "");
		// // System.out.printf("op1"+op1);
		// // System.exit(1);
		// String op2 = ops[3].replaceAll(",", "");
		// // System.exit(1);
		// // String z =getparams(regs);
		// System.out.printf(
		// "int %s = ((float)%s == (float) %s) ; // lt-nan\n", to,
		// op1, op2);
		// // System.exit(1);
		//
		// }

		else if (opname.equals("check-cast")) {
			String regi = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			System.out.printf("checkcast %s %s\n", type, regi);
			il.append(new ALOAD(locals.didx2jvmidxstr(regi)));
			// il.append(m_currentInstructionFactory
			// .createCheckCast(new ObjectType(toJavaName(type))));
			if (!type.startsWith("[")) {
				if (type.startsWith("L")) {
					type = type.substring(1);
					type = type.replaceAll(";", "");
				}
				// type = type.replace("."/");
			}
			il.append(m_currentInstructionFactory
					.createCheckCast(new ObjectType(type)));

			// il.append(new CHECKCAST(cpg.addClass(toJavaName(type))));
			il.append(new ASTORE(locals.didx2jvmidxstr(regi)));
		}

		else if (opname.equals("instance-of")) {
			String regfrom = ops[1].replaceAll(",", "");
			String regto = ops[2].replaceAll(",", "");

			String type = ops[3].replaceAll(",", "");
			System.out.printf("instanceof %s %s\n", type, regfrom);
			il.append(new ALOAD(locals.didx2jvmidxstr(regto)));
			il.append(new INSTANCEOF(Utils.doAddClass(cpg, type)));
			// il.append(new INSTANCEOF(cpg.addClass(toJavaName(type))));
			il.append(new ISTORE(locals.didx2jvmidxstr(regfrom)));
		}

		else if (opname.equals("const-string")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ""; // ops[2].replaceAll(",", "");
			jlog.info("ops.length:" + ops.length);
			jlog.info("dcl:" + dcl);

			jlog.info(Arrays.toString(ops));
			jlog.info(Arrays.toString(comps));

			int theString = Integer.parseInt(comps[1].substring(0, 2), 16);
			jlog.info("th=" + theString);

			String chosenString = _apa.getString(theString);

			jlog.info("chosenString:" + chosenString);

			/*
			 * int idx = 2; String z = ops[2]; if (ops.length > 5) for (int j =
			 * 3; j < ops.length - 2; j++) { z = z + " " + ops[j]; } while
			 * (!ops[idx].endsWith("\"")) { idx++; }
			 * 
			 * jlog.info("z:" + z); jlog.info("idx:" + idx);
			 * field = z;
			 */
			System.out.printf("String %s = %s;\n", regfrom, field);
			// int ref = cpg.addString(field.substring(1, field.length() - 1));

			int ref = cpg.addString(chosenString);
			il.append(new LDC(ref));
			il.append(new ASTORE(locals.didx2jvmidxstr(regfrom)));

			locals.annotateLV(regfrom, "Ljava/lang/String;");

		}

		else if (opname.equals("const/16")) {
			String regfrom = ops[1].replaceAll(",", "");
			String type = ops[2].replaceAll(",", "");
			String value = ops[3].replaceAll(",", "");
			System.out.printf("%s %s = (%s) %s;\n", type, regfrom, type, value);
			short intval = Short.parseShort(value);
			int ref = cpg.addInteger(intval);
			
			il.append(new LDC(ref));
			il.append(new ISTORE(locals.didx2jvmidxstr(regfrom)));
		}

		else if (opname.equals("move-object/from16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("%s =  %s;\n", regto, regfrom);
			il.append(new ALOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ASTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("move-object")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("%s =  %s;\n", regto, regfrom);
			il.append(new ALOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ASTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("add-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s + (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IADD());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("mul-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s * (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IMUL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("add-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s + (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LADD());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("xor-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s xor (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LXOR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("or-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s or (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LOR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("shl-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s <<  (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LSHL());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("and-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s AND (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LAND());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("sub-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s - (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ISUB());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("rem-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s %% (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IREM());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
		} else if (opname.equals("rem-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s %% (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LREM());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("rem-float/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("float %s =  (float)%s %% (float)%s;\n", regto,
					regto, regfrom);
			il.append(new FLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new FREM());
			il.append(new FSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("rem-double/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("double %s =  (double)%s %% (double)%s;\n",
					regto, regto, regfrom);
			il.append(new DLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new DREM());
			il.append(new DSTORE(locals.didx2jvmidxstr(regto)));
		}

	

		else if (opname.equals("mul-int/lit16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IMUL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s * (%s)%s;\n", regto, regfrom,
					type, val);

		} else if (opname.equals("rem-int/lit8")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IREM());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s %% (%s)%s;\n", regto,
					regfrom, type, val);

		} else if (opname.equals("rem-int/lit16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IREM());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s %% (%s)%s;\n", regto,
					regfrom, type, val);

		}

		else if (opname.equals("shl-int/lit8")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new ISHL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s << (%s)%s;\n", regto,
					regfrom, type, val);

		}

		else if (opname.equals("shr-int/lit8")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new ISHR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s >> (%s)%s;\n", regto,
					regfrom, type, val);

		}

		else if (opname.equals("shr-int")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String anz = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ILOAD(locals.didx2jvmidxstr(anz)));
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new ISHR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s >> %s;\n", regto, regfrom,
					anz);

		}

		else if (opname.equals("shr-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String anz = ops[3].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LLOAD(locals.didx2jvmidxstr(anz)));
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new LSHR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s >> %s;\n", regto, regfrom,
					anz);
		}

		else if (opname.equals("ushr-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String anz = ops[3].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LLOAD(locals.didx2jvmidxstr(anz)));
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new LUSHR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s >> %s;\n", regto, regfrom,
					anz);
		}

		else if (opname.equals("shl-int")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String anz = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ILOAD(locals.didx2jvmidxstr(anz)));
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new ISHL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s >> %s;\n", regto, regfrom,
					anz);

		}

		else if (opname.equals("ushr-int/lit8")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IUSHR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s << (%s)%s;\n", regto,
					regfrom, type, val);

		}
		
		else if (opname.equals("ushr-int")) {
			     String regto = ops[1].replaceAll(",", "");
			     String regfrom = ops[2].replaceAll(",", "");
			     String anz = ops[3].replaceAll(",", "");
			     il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			     il.append(new ILOAD(locals.didx2jvmidxstr(anz)));
			     il.append(new IUSHR());
			     il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
			     System.out.printf("int %s =  (int )%s >> %s; [ushr-int, contrib by maxim.f]\n", regto, regfrom,
			       anz);
			   }

		else if (opname.equals("or-int/lit8")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s OR (%s)%s;\n", regto,
					regfrom, type, val);

		}

		else if (opname.equals("add-int/lit16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);
			il.append(new IADD());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

			System.out.printf("int %s =  (int )%s + (%s)%s;\n", regto, regfrom,
					type, val);

		}

		else if (opname.equals("mul-float/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("float %s =  (float )%s * (float)%s;\n", regto,
					regto, regfrom);
			il.append(new FLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new FMUL());
			il.append(new FSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("mul-int")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("int %s =  (int)%s * (int)%s;\n", regto, regop1,
					regop2);
			il.append(new ILOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new IMUL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("add-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s + (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LADD());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("shl-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s << (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LSHL());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("and-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s and (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LAND());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("xor-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s + (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LXOR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("rem-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s %% (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LREM());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("mul-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s * (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LMUL());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("sub-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s - (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LSUB());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("div-long")) {
			String regto = ops[1].replaceAll(",", "");
			String regop1 = ops[2].replaceAll(",", "");
			String regop2 = ops[3].replaceAll(",", "");

			System.out.printf("long %s =  (long)%s - (long)%s;\n", regto,
					regop1, regop2);
			il.append(new LLOAD(locals.didx2jvmidxstr(regop2)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regop1)));
			il.append(new LDIV());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("div-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s / (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IDIV());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("shl-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s <<  (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ISHL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("ushr-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s >>  (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IUSHR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
		} 
		else if (opname.equals("shr-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s >>  (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ISHR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("xor-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s xor (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IXOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("or-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s OR (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("and-int/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s AND (int)%s;\n", regto, regto,
					regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regto)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new IAND());
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("sub-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s - (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LSUB());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("shr-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s >> (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LSHR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("mul-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s * (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LMUL());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("div-long/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s / (long)%s;\n", regto,
					regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LDIV());
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("add-float/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("float %s = (float) %s + (float)%s;\n", regto,
					regto, regfrom);

			il.append(new FLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new FADD());
			il.append(new FSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("add-double/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("double %s = (double) %s + (double)%s;\n", regto,
					regto, regfrom);
			il.append(new DLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new DADD());
			il.append(new DSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("div-double/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("double %s = (double) %s %% (double)%s;\n",
					regto, regto, regfrom);
			il.append(new DLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new DDIV());
			il.append(new DSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("sub-double/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("double %s = (double) %s - (double)%s;\n", regto,
					regto, regfrom);
			il.append(new DLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new DSUB());
			il.append(new DSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("mul-double/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("double %s = (double) %s * (double)%s;\n", regto,
					regto, regfrom);
			il.append(new DLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new DMUL());
			il.append(new DSTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("sub-float/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("float %s = (float) %s - (float)%s;\n", regto,
					regto, regfrom);
			il.append(new FLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new FSUB());
			il.append(new FSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("div-float/2addr")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("float %s = (float) %s / (float)%s;\n", regto,
					regto, regfrom);
			il.append(new FLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new FDIV());
			il.append(new FSTORE(locals.didx2jvmidxstr(regto)));
		}

		else if (opname.equals("add-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IADD());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));
			//String fmt = ;
			logfmtstr3(regres, regadd1, regadd2, "int %s =  (int)%s + (int)%s;\n");
			// String z = System.out.form

			// System.out.printf("int %s =  (int)%s + (int)%s;\n", regres,
			// regadd1, regadd2);
		}

		else if (opname.equals("and-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IAND());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));
			logfmtstr3(regres, regadd1, regadd2, "int %s =  (int)%s and (int)%s;\n");
			
		}

		else if (opname.equals("rem-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IREM());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			logfmtstr3(regres, regadd1, regadd2, "int %s =  (int)%s %% (int)%s;\n");

		} else if (opname.equals("div-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IDIV());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			logfmtstr3(regres, regadd1, regadd2, "int %s =  (int)%s / (int)%s;\n");

		}

		else if (opname.equals("div-float")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new FDIV());
			il.append(new FSTORE(locals.didx2jvmidxstr(regres)));

			logfmtstr3(regres, regadd1, regadd2, "float %s =  (float)%s / (float)%s;\n");

		}

		else if (opname.equals("div-double")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new DDIV());
			il.append(new DSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("double %s =  (double)%s / (double)%s;\n",
					regres, regadd1, regadd2);
		}
		else if (opname.equals("rem-double")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new DREM());
			il.append(new DDIV());
			il.append(new DSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("double %s =  (double)%s / (double)%s;\n",
					regres, regadd1, regadd2);

		} else if (opname.equals("mul-double")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new DMUL());
			il.append(new DSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("double %s =  (double)%s * (double)%s;\n",
					regres, regadd1, regadd2);

		}

		else if (opname.equals("mul-float")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new FMUL());
			il.append(new FSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("float %s =  (float)%s * (float)%s;\n", regres,
					regadd1, regadd2);

		} else if (opname.equals("sub-float")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new FSUB());
			il.append(new FSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("float %s =  (float)%s - (float)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("sub-double")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new DSUB());
			il.append(new DSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("double %s =  (double)%s - (double)%s;\n",
					regres, regadd1, regadd2);

		} else if (opname.equals("add-float")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new FLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new FSUB());
			il.append(new FSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("float %s =  (float)%s + (float)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("add-double")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new DLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new DSUB());
			il.append(new DSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("double %s =  (double)%s + (double)%s;\n",
					regres, regadd1, regadd2);

		}

		else if (opname.equals("sub-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new ISUB());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("int %s = (int) %s - (int)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("or-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("int %s = (int) %s OR (int)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("or-long")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new LOR());
			il.append(new LSTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("long %s = (long) %s OR (long)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("xor-int")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String regadd2 = ops[3].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd2)));
			il.append(new IXOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("int %s = (int) %s XOR (int)%s;\n", regres,
					regadd1, regadd2);

		}

		else if (opname.equals("add-int/lit8")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IADD());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s + (%s) %s;\n", regres, regadd1, typ,
					val);

		} else if (opname.equals("and-int/lit16")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IAND());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s && (%s) %s;\n", regres, regadd1, typ,
					val);

		} else if (opname.equals("xor-int/lit16")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IXOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s XOR (%s) %s;\n", regres, regadd1, typ,
					val);
		} else if (opname.equals("xor-int/lit8")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IXOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s XOR (%s) %s;\n", regres, regadd1, typ,
					val);
		} else if (opname.equals("or-int/lit16")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s OR (%s) %s;\n", regres, regadd1, typ,
					val);

		} else if (opname.equals("div-int/lit16")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IDIV());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s /  (%s) %s;\n", regres, regadd1, typ,
					val);

		} else if (opname.equals("and-int/lit8")) {
			// for (int k = 0; k < 5000 ; k++)
			// jlog.info("AAAAAAAAAAAa");
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IAND());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("%s =  %s && (%s) %s;\n", regres, regadd1, typ,
					val);

		}

		else if (opname.equals("mul-int/lit8")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IMUL());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

			System.out.printf("int %s =  (int) %s * (%s) %s;\n", regres,
					regadd1, typ, val);

		} else if (opname.equals("div-int/lit8")) {
			String regres = ops[1].replaceAll(",", "");
			String regadd1 = ops[2].replaceAll(",", "");
			String typ = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");

			System.out.printf("int %s =  (int) %s / (%s) %s;\n", regres,
					regadd1, typ, val);
			il.append(new ILOAD(locals.didx2jvmidxstr(regadd1)));
			int ival = Integer.parseInt(val);  
			getShortestIntegerPush(cpg, ival, il);

//			il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			il.append(new IDIV());
			il.append(new ISTORE(locals.didx2jvmidxstr(regres)));

		} else if (opname.equals("sparse-switch")) {
			String reg = ops[1].replaceAll(",", "");
			jlog.info(reg);
			String reg2 = ops[2].replaceAll(",", "");
			jlog.info(reg2);
			DalvikCodeLine dclx = bl1.getByLogicalOffset(reg2);
			int phys = dclx.getMemPos();
			int curpos = dcl.getPos();
			int magic = getAPA().getShort(phys);
			if (magic != 0x0200) {
				Utils.stopAndDump("wrong magic");
			}
			int size = getAPA().getShort(phys + 2);
			int[] jumpcases = new int[size];
			int[] offsets = new int[size];
			InstructionHandle[] ihh = new InstructionHandle[size];
			for (int k = 0; k < size; k++) {
				jumpcases[k] = getAPA().getShort(phys + 4 + 4 * k);
			}
			for (int k = 0; k < size; k++) {
				offsets[k] = getAPA().getShort(phys + 4 + 4 * (size + k));
			}

			for (int k = 0; k < size; k++) {
				int newoffset = offsets[k] + curpos;
				String zzzz = Utils.getFourCharHexString(newoffset);
				ihh[k] = ic.get(zzzz);
				jlog.info("ii:" + k + " pos:" + curpos + " "
						+ offsets[k] + ":" + newoffset + ":" + ihh[k]);

			}

			int defaultpos = dcl.getNext().getPos();
			String zzzz = Utils.getFourCharHexString(defaultpos);

			InstructionHandle theDefault = ic.get(zzzz);

			jlog.info("sparse-switch at:" + reg2 + ":" + phys + ":"
					+ magic + ":" + size + ":" + Arrays.toString(jumpcases)
					+ ":" + Arrays.toString(offsets));

			il.append(new ILOAD(locals.didx2jvmidxstr(reg)));
			LOOKUPSWITCH ih = new LOOKUPSWITCH(jumpcases, ihh, theDefault);

			il.append(ih);

		} else if (opname.equals("packed-switch")) {

			/*
			 * const int kInstrLen = 3; u2 size; s4 firstKey; s4 entries;
			 */
			/*
			 * Packed switch data format: ushort ident = 0x0100 magic value
			 * ushort size number of entries in the table int first_key first
			 * (and lowest) switch case value int targets[size] branch targets,
			 * relative to switch opcode
			 * 
			 * Total size is (4+size2) 16-bit code units.
			 */

			String reg = ops[1].replaceAll(",", "");
			String data = ops[2].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(reg)));
			jlog.info("pso:" + relativeandmne[0]);
			jlog.info("pso:" + relativeandmne[1]);
			TABLESWITCH tb = new DeferredTableSwitch(relativeandmne[0], data);
			il.append(tb);
			System.out.printf("switch  (%s), data(%s) start;\n", reg, data);

		}

		else if (opname.equals("packed-switch-data")) {
			jlog.info("psd:" + offsetandcode[0]);
			jlog.info("psd:" + offsetandcode[1]);

			String magic = offsetandcode[1].split(" ")[0];
			if (!magic.equals("0001")) {
				Utils.stopAndDump("wrong magic");
			}
			String anz = offsetandcode[1].split(" ")[1];
			int i_anz = Integer.parseInt(anz.substring(2, 4), 16) * 16
					+ Integer.parseInt(anz.substring(0, 2), 16);

			jlog.info("anz=" + i_anz);

			int length = 2 * (4 + i_anz * 2);
			jlog.info("length=" + length);

			// jlog.info(offsetandcode[1].split(" ")[1]);
			// jlog.info(offsetandcode[1].split(" ")[2]);
			// jlog.info(offsetandcode[2]);

			int offset = Integer.parseInt(offsetandcode[0], 16);
			// jlog.info(offsetandcode[1].split("")[2]);
			jlog.info("offset:" + offset + ":"
					+ Integer.toString(offset, 16));
			byte[] b = new byte[0];
			APKAccess apa = this.getAPA();
			try {

				b = apa.getBytesFromClassesDex(offset, length);
			} catch (Exception e) {
				e.printStackTrace();
				Utils.stopAndDump("no file, no finish" + e);

			}
			int pos = 4;
			int[] offsets = new int[i_anz];
			InstructionHandle[] ihh = new InstructionHandle[i_anz];
			int startindex = Utils.intFrombytes(b, pos);
			pos += 4;
			jlog.info("startindex = " + startindex);
			// Utils.stopAndDump("stop here:"+b[0]+":"+b[1]+":"+b[2]);

			// int startindex = 9;
			// String reg = ops[1].replaceAll("\\(", "").replaceAll("\\)", "");
			//
			// System.out.printf("switch  (%s) end;\n", reg);
			//			
			// int pos = Integer.parseInt(relativeandmne[0], 16);
			// jlog.info(pos);
			InstructionHandle[] hl = ic.getInstructions()
					.getInstructionHandles();
			// // InstructionList ss = il;
			boolean tswfound = false;
			// InstructionHandle target = null;
			// InstructionHandle[] handles;
			DeferredTableSwitch dts = null;
			InstructionHandle dts_h = null;
			int[] hi;
			// ArrayList<InstructionHandle> al = new
			// ArrayList<InstructionHandle>();
			for (int i = 0; i < hl.length; i++) {
				InstructionHandle z = hl[i];
				// // jlog.info(z);
				if (!tswfound
						&& z.getInstruction() instanceof DeferredTableSwitch) {
					dts = (DeferredTableSwitch) z.getInstruction();
					dts_h = z;
					jlog.info("dts.addr=" + dts.getAddr());

					// GOTO g = (GOTO) hl[i + 2].getInstruction(); // We have a
					// nop
					// // inbetween
					// jlog.info(g.getTarget());
					// target = g.getTarget();
					tswfound = true;
					// al.add(hl[i + 4]);
				}
			}
			String startoffset = dts.getOrigOffset();

			jlog.info("Addr=" + dts.getAddr());
			jlog.info("Offset=" + dts.getOrigOffset());

			// for (Enumeration<String> e = ic.keys(); e.hasMoreElements();) {
			// String key = e.nextElement();
			// jlog.info(key);
			// InstructionHandle ztarget = ic.get(key);
			// jlog.info(ztarget + ":" + dts.getAddr());
			// if (ztarget.equals(dts_h)) {
			// startoffset = key;
			// }
			// }

			int i_startoffset = Integer.parseInt(startoffset, 16);

			for (int ii = 0; ii < i_anz; ii++) {
				offsets[ii] = Utils.intFrombytes(b, pos);
				String zzzz = Utils.getFourCharHexString(offsets[ii]
						+ i_startoffset);
				ihh[ii] = ic.get(zzzz);
				jlog.info("ii:" + ii + " pos:" + pos + " "
						+ offsets[ii]);
				if (ihh[ii] == null) {
					jlog.severe("null pointer in jump target:" + pos + ":"
							+ zzzz + " " + offsets[ii] + " " + i_startoffset);

				}
				pos = pos + 4;
			}

			// for (int i = 0; i < offsets.length; i++) {
			// int address = i_startoffset+offsets[i];
			// }
			// if (false) {
			// if (tswfound) {
			// if (z.getInstruction() instanceof GOTO) {
			// GOTO g = (GOTO) hl[i].getInstruction();
			// if (g.getTarget().equals(target))
			//
			// if (!(hl[i + 2].getInstruction() instanceof NOP))
			// al.add(hl[i + 2]);
			// }
			// }
			//
			// }
			// handles = al.toArray(new InstructionHandle[0]);
			hi = new int[i_anz];
			for (int ij = 0; ij < i_anz; ij++) {
				hi[ij] = ij + startindex;
			}
			// <<<<<<< DalvikToJVM.java
			// il.append(new NOP());
			// InstructionHandle thedefault = ic.getInstructions().append(dts_h,
			// new NOP());
			// il.append(thedefault, new NOP());
			// =======
			// il.append(new NOP());
			z_il += "altered";// show that something changed
			InstructionHandle thedefault = ic.getInstructions().append(dts_h,
					new NOP());
			ic.getInstructions().append(thedefault, new NOP());
			// >>>>>>> 1.8
			TABLESWITCH tsw = new TABLESWITCH(hi, ihh, thedefault);

			try {
				ic.getInstructions().append(dts_h, tsw);
				ic.getInstructions().delete(dts_h);
				// dts.setTarget(handles);
			} catch (Exception e) {
				Utils.stopAndDump("crashed during replacement of ts" + e);
				e.printStackTrace();
			}

		}

		else if (opname.equals("fill-array-data")) {
			String thearray = ops[1].replaceAll(",", "");
			String theoffset = ops[2].replaceAll(",", "");
			jlog.info(thearray + ":" + theoffset);
			while (theoffset.length() > 4 && theoffset.startsWith("0")) {
				theoffset = theoffset.substring(1);
			}

			DalvikCodeLine x = dcl.getPrev();
			String type = "";
			while (x != null) {

				if (x.getOpname().equals("new-array")) {
					type = x.getOps()[3];
					break;
				}
				x = x.getNext();
			}

			jlog.info("found array type:" + type);
			// Utils.stopAndDump("and the type is:"+type);
			jlog.info(thearray + ":" + theoffset);

			jlog.info("psd:" + offsetandcode[0]);
			jlog.info("psd:" + offsetandcode[1]);
			jlog.info("pso:" + relativeandmne[0]);
			jlog.info("pso:" + relativeandmne[1]);
			// InstructionHandle ih = ic.get(theoffset);
			DalvikCodeLine dcl1 = bl1.getByLogicalOffset(theoffset);
			jlog.info("found:" + dcl1);
			int z = dcl1.getMemPos();
			String str_units = dcl1.getOpcode()
					.replaceAll("array-data \\(", "");
			str_units = str_units.replaceAll("\\)", "");
			str_units = str_units.replaceAll("units", "");
			int units = Integer.parseInt(str_units.trim());
			jlog.info("units=" + units);
			// String hexz = Utils.getFourCharHexString(z);
			APKAccess apa = this.getAPA();
			byte[] b = null;
			try {

				b = apa.getBytesFromClassesDex(0, -1);
			} catch (Exception e) {
				e.printStackTrace();
				Utils.stopAndDump("no file, no finish" + e);
			}
			int magic = b[z + 1] * 256 + b[z];
			if (magic != 3 * 256) {
				Utils.stopAndDump("wrong magic:" + magic);
			}
			int bytesperentry = b[z + 2];
			int numelem = b[z + 5] * 256 + b[z + 4];
			jlog.info("bpe=" + bytesperentry);
			jlog.info("bpe=" + numelem);
			Number[] numarr = null;
			if (bytesperentry == 8) {
				if (type.endsWith("J")) {
					numarr = new Long[numelem];
				} else {
					numarr = new Double[numelem];
				}
			} else if (bytesperentry == 4) {
				numarr = new Integer[numelem];
			} else if (bytesperentry == 2) {
				numarr = new Short[numelem];

			} else if (bytesperentry == 1) {
				numarr = new Byte[numelem];
			}

			for (int i = 0; i < numelem; i++) {
				if (bytesperentry == 8) {
					long zz = Utils.longFrombytes(b, z + 4 + i * bytesperentry);
					if (type.endsWith("J")) {
						numarr[i] = new Long(zz);
					} else
						numarr[i] = Double.longBitsToDouble(zz);

					// numarr = new Double[units];

				} else if (bytesperentry == 4) {
					int zz = Utils.intFrombytes(b, z + 4 + i * bytesperentry);
					numarr[i] = zz;
				} else if (bytesperentry == 2) {
					short zz = (short) Utils.shortFrombytes(b, z + 4 + (i + 2)
							* bytesperentry);
					numarr[i] = zz;
				} else if (bytesperentry == 1) {
					byte zz = b[z + 4 + i * bytesperentry];
					numarr[i] = zz;
				}

			}

			for (int i = 0; i < numelem; i++) {
				if (bytesperentry == 8) {
					// int zz = Utils.intFrombytes(b,z+4+i*bytesperentry);
					// numarr[i]=zz;
					InstructionList il2 = new InstructionList();
					il2.append(new ALOAD(locals.didx2jvmidxstr(thearray)));
					getShortestIntegerPush(cpg, i, il2);
					// getShortestIntegerPush(cpg, (Integer) numarr[i], il2);

					// il2.append(new LDC(cpg.i));
					// il2.append(new ICONST((Integer) numarr[i]));
					if (type.endsWith("J")) {
						il2.append(new LDC2_W(cpg.addLong((Long) numarr[i])));
						il2.append(new LASTORE());
					} else {
						il2
								.append(new LDC2_W(cpg
										.addDouble((Double) numarr[i])));
						il2.append(new DASTORE());
					}
					il.append(il2);

				} else if (bytesperentry == 4) {
					// int zz = Utils.intFrombytes(b,z+4+i*bytesperentry);
					// numarr[i]=zz;
					InstructionList il2 = new InstructionList();
					il2.append(new ALOAD(locals.didx2jvmidxstr(thearray)));
					getShortestIntegerPush(cpg, i, il2);
					getShortestIntegerPush(cpg, (Integer) numarr[i], il2);

					// il2.append(new LDC(cpg.i));
					// il2.append(new ICONST((Integer) numarr[i]));
					il2.append(new IASTORE());
					il.append(il2);

				} else if (bytesperentry == 2) {
					InstructionList il2 = new InstructionList();
					il2.append(new ALOAD(locals.didx2jvmidxstr(thearray)));
					getShortestIntegerPush(cpg, i, il2);
					getShortestIntegerPush(cpg, (Short) numarr[i], il2);
					il2.append(new CASTORE());
					il.append(il2);
				} else if (bytesperentry == 1) {
					InstructionList il2 = new InstructionList();
					il2.append(new ALOAD(locals.didx2jvmidxstr(thearray)));
					getShortestIntegerPush(cpg, i, il2);
					getShortestIntegerPush(cpg, (Byte) numarr[i], il2);
					il2.append(new BASTORE());
					il.append(il2);
				}
			}

			// Utils.stopAndDump("fill array data, end:" + ih + ":" + hexz + "("
			// + z + "):" + magic + ":" + bytesperentry);

		}

		else if (opname.startsWith("array-data")) {
			il.append(new NOP());
			System.out.printf("%s (already handled) ;\n", opname);

		}

		else if (opname.startsWith("sparse-switch-data")) {
			il.append(new NOP());
			System.out.printf("%s (already handled) ;\n", opname);

		}

		else if (opname.equals("neg-float")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new FNEG());
			il.append(new FSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("float %s -=  %s ;\n", thefloat, theint);

		}

		else if (opname.equals("neg-int")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new INEG());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("int %s -=  %s ;\n", thefloat, theint);

		}
		
		else if (opname.equals("not-int")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new ICONST(-1));
			il.append(new IXOR());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("int %s ~=  %s ;\n", thefloat, theint);

		}

		else if (opname.equals("not-long")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new LCONST(-1));
			il.append(new LXOR());
			il.append(new LSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("int %s ~=  %s ;\n", thefloat, theint);

		}

		
		else if (opname.equals("neg-double")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new DNEG());
			il.append(new DSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("double %s -=  %s ;\n", thefloat, theint);

		}

		else if (opname.equals("neg-long")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new LNEG());
			il.append(new LSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("long %s -=  %s ;\n", thefloat, theint);

		}

		else if (opname.equals("int-to-float")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2F());
			il.append(new FSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("float %s =  (float) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("long-to-int")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new L2I());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("int %s =  (int) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("long-to-double")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(theint)));
			il.append(new L2D());
			il.append(new DSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("double %s =  (double) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("int-to-double")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2D());
			il.append(new DSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("double %s =  (double) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("int-to-long")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			;
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2L());
			il.append(new LSTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("long %s =  (long) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("int-to-short")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			;
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2S());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("short %s =  (short) %s ;\n", thefloat, theint);

		} else if (opname.equals("int-to-byte")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			;
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2B());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("byte %s =  (byte) %s ;\n", thefloat, theint);

		} else if (opname.equals("int-to-char")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			;
			il.append(new ILOAD(locals.didx2jvmidxstr(theint)));
			il.append(new I2C());
			il.append(new ISTORE(locals.didx2jvmidxstr(thefloat)));

			System.out.printf("byte %s =  (byte) %s ;\n", thefloat, theint);

		} else if (opname.equals("float-to-double")) {
			String theint = ops[1].replaceAll(",", "");
			String thefloat = ops[2].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new F2D());
			il.append(new DSTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("double %s =  (double) %s ;\n", thefloat, theint);

		} else if (opname.equals("double-to-float")) {
			String theint = ops[1].replaceAll(",", "");
			String thefloat = ops[2].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new D2F());
			il.append(new FSTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("float %s =  (float) %s ;\n", thefloat, theint);

		} else if (opname.equals("double-to-long")) {
			String theint = ops[1].replaceAll(",", "");
			String thefloat = ops[2].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new D2L());
			il.append(new LSTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("lobf %s =  (double) %s ;\n", thefloat, theint);

		}

		else if (opname.equals("double-to-int")) {
			String theint = ops[1].replaceAll(",", "");
			String thefloat = ops[2].replaceAll(",", "");
			il.append(new DLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new D2I());
			il.append(new ISTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("int %s =  (int) %s ;\n", thefloat, theint);

		} else if (opname.equals("float-to-int")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new F2I());
			il.append(new ISTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("int %s =  (int) %s ;\n", thefloat, theint);

		} else if (opname.equals("long-to-float")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new LLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new L2F());
			il.append(new FSTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("float %s =  (float) %s ;\n", thefloat, theint);
		} else if (opname.equals("float-to-long")) {
			String thefloat = ops[1].replaceAll(",", "");
			String theint = ops[2].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(thefloat)));
			il.append(new F2L());
			il.append(new LSTORE(locals.didx2jvmidxstr(theint)));

			System.out.printf("long %s =  (long) %s ;\n", thefloat, theint);

		} else if (opname.equals("rem-float")) {
			String resfloat = ops[1].replaceAll(",", "");
			String opfloat1 = ops[1].replaceAll(",", "");
			String opfloat2 = ops[1].replaceAll(",", "");
			il.append(new FLOAD(locals.didx2jvmidxstr(resfloat)));
			il.append(new FLOAD(locals.didx2jvmidxstr(opfloat1)));
			il.append(new FREM());
			il.append(new FSTORE(locals.didx2jvmidxstr(opfloat2)));

			System.out.printf("float %s =  (float) %s %% %s ;\n", resfloat,
					opfloat1, opfloat2);
		}

		else if (opname.equals("move")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s;\n", regto, regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		} else if (opname.equals("move-wide")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long )%s;\n", regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("move-wide/from16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long )%s;\n", regto, regfrom);
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("move/from16")) {
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("int %s =  (int)%s;\n", regto, regfrom);
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));

		}

		else if (opname.equals("+execute-inline")) {
			OpCodeHandler_ODEX.handle_exec_inline(regs, ops, il, cpg, locals,
					bl1, dcl);
		}

		/*** invokes go here **/
		else if (opname.equals("invoke-static")) {
			handle_invoke_static(regs, ops, il, cpg, locals, bl1, dcl);
		} else if (opname.equals("invoke-static/range")) {
			handle_invoke_static(regs, ops, il, cpg, locals, bl1, dcl);
		} else if (opname.equals("invoke-direct")) {
			handle_invoke_direct(regs, ops, il, cpg, locals);
		} else if (opname.equals("+invoke-direct-empty")) {
			handle_invoke_direct(regs, ops, il, cpg, locals);

		} else if (opname.equals("invoke-interface")) {
			handle_invoke_interface(regs, ops, il, cpg, locals);
			// System.exit(0);
		} else if (opname.equals("invoke-interface/range")) {
			handle_invoke_interface(regs, ops, il, cpg, locals);
			// System.exit(0);
		} else if (opname.equals("invoke-super")) {
			handle_invoke_super(regs, ops, il, cpg, locals);
			// System.exit(0);
		} else if (opname.equals("+invoke-super-quick")) {
			OpCodeHandler_ODEX.handle_invoke_super_quick(regs, ops, il, cpg,
					locals, bl1, dcl);
			// System.exit(0);
		} else if (opname.equals("invoke-virtual-direct")) {
			handle_invoke_virtual_direct(regs, ops);
		}

		else if (opname.equals("invoke-direct/range")) {
			handle_invoke_direct_range(regs, ops, il, cpg, locals);
		} else if (opname.equals("invoke-virtual")) {
			handle_invoke_virtual(regs, ops, il, cpg, locals, bl1, dcl);
			// } else if (opname.equals("+invoke-virtual-direct")) {
			// handle_invoke_virtual_direct(regs, ops, il, cpg, locals, bl1,
			// dcl);
		} else if (opname.equals("invoke-virtual/range")) {
			// String regto = regs[0];
			// String regfrom = ops[2].replaceAll(",", "");
			// System.out.printf("(%s)->  %s;\n", regto, regfrom);
			handle_invoke_virtual(regs, ops, il, cpg, locals, bl1, dcl);
		} else if (opname.equals("+invoke-virtual-quick")) {
			// String regto = regs[0];
			// String regfrom = ops[2].replaceAll(",", "");
			// System.out.printf("(%s)->  %s;\n", regto, regfrom);
			OpCodeHandler_ODEX.handle_invoke_virtual_quick(regs, ops, il, cpg,
					locals, bl1, dcl);

		} else if (opname.equals("+iput-object-quick")) {
			// String regto = regs[0];
			// String regfrom = ops[2].replaceAll(",", "");
			// System.out.printf("(%s)->  %s;\n", regto, regfrom);
			OpCodeHandler_ODEX.handle_iput_object_quick(ops, il, cpg, locals);

		} else if (opname.equals("invoke-super/range")) {
			// String regto = regs[0];
			// String regfrom = ops[2].replaceAll(",", "");
			// System.out.printf("(%s)->  %s;\n", regto, regfrom);
			handle_invoke_super(regs, ops, il, cpg, locals);

		}

		/*** invokes end here ***/

		else if (opname.equals("iput-boolean")) {
			handle_iput_boolean(ops, il, cpg, locals);
		} else if (opname.equals("iput-short")) {
			handle_iput_short(ops, il, cpg, locals);
		}

		else if (opname.equals("iput-char")) {
			handle_iput_char(ops, il, cpg, locals);
		} else if (opname.equals("iput-byte")) {
			handle_iput_byte(ops, il, cpg, locals);

		} else if (opname.equals("aput-boolean")) {
			handle_aput_boolean(ops, il, cpg, locals);
		} else if (opname.equals("aput-char")) {
			handle_aput_char(ops, il, cpg, locals);
		} else if (opname.equals("aput-short")) {
			handle_aput_short(ops, il, cpg, locals);
		} else if (opname.equals("aput-byte")) {
			handle_aput_byte(ops, il, cpg, locals);
		} else if (opname.equals("aput-object")) {
			handle_aput_object(ops, il, cpg, locals);
		} else if (opname.equals("aget-boolean")) {
			handle_aget_boolean(ops, il, cpg, locals);
		} else if (opname.equals("aget-byte")) {
			handle_aget_byte(ops, il, cpg, locals);
		} else if (opname.equals("aget-short")) {
			handle_aget_short(ops, il, cpg, locals);
		} else if (opname.equals("aget-char")) {
			handle_aget_char(ops, il, cpg, locals);
		} else if (opname.equals("aget-object")) {
			handle_aget_object(ops, il, cpg, locals);
		} else if (opname.equals("array-length")) {
			handle_array_length(ops, il, cpg, locals);

		} else if (opname.equals("aget")) {
			handle_aget(ops, il, cpg, locals);
		} else if (opname.equals("aget-wide")) {
			handle_aget(ops, il, cpg, locals);
		} else if (opname.equals("aput")) {
			handle_aput(ops, il, cpg, locals);
		} else if (opname.equals("aput-wide")) {
			handle_aput(ops, il, cpg, locals);
		} else if (opname.equals("return-void")) {
			il.append(new RETURN());
//			jlog.info();
			jlog.info("return;");
		} else if (opname.equals("return")) {
			String regoper = ops[1].replaceAll(",", "");
			int jvmoper = locals.didx2jvmidxstr(regoper);
			System.out.printf("return %s;\n", jvmoper);
			String signature = mg.getSignature();
			if (signature.endsWith(")S") || signature.endsWith(")I")
					|| signature.endsWith(")B") || signature.endsWith(")Z")
					|| signature.endsWith(")C")) {
				// jlog.info(locals.ht.get(regoper));
				// dumpRegs(locals);

				il.append(new ILOAD(jvmoper));
				il.append(new IRETURN());
			} else if (signature.endsWith(")F")) {
				il.append(new FLOAD(jvmoper));
				il.append(new FRETURN());
			} else {
				Utils.stopAndDump("unknown return in:" + signature);
			}
			// jlog.info(il);
			// stopAndDump("stop for opname:"+opname);
		} else if (opname.equals("return-wide")) {
			String regoper = ops[1].replaceAll(",", "");
			int jvmoper = locals.didx2jvmidxstr(regoper);

			System.out.printf("return %s;", regoper);
			il.append(new DLOAD(jvmoper));
			il.append(new DRETURN());

			/* Guess return type from signature */

			// System.exit(0);
		} else if (opname.equals("return-object")) {
			String regoper = ops[1].replaceAll(",", "");
			int jvmoper = locals.didx2jvmidxstr(regoper);
			il.append(new ALOAD(jvmoper));
			il.append(new ARETURN());
			// jlog.info(il);

			System.out.printf("return %s;", regoper);
		}
			/*
			 * STILL MISSING:
			 * from BadDalvikOpcodes
				move-wide -- has no description
				move/16 -- has no description
				move-object/16 -- has no description
				invoke-virtual-quick/range
				invoke-super-quick/range
				goto/32 - no desc. but i'm guessing this is "Unconditional jump by 32 bit offset"?
				filled-new-array-range
				const-string-jumbo
				
			 * DONE (or kludged):
			 * iput-wide-quick -- used the same routine as iput-wide
			 * iput-quick -- used iput for this
			 * iget-wide-quick
			 * iget-quick
			 */
		/** added by IG **/
		else if(opname.equals("sub-int/lit16")) {
			// sub-int/lit16 - Calculates vy - lit16 and stores the result into vx.
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			// Load int from local variable
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			// Push item from runtime constant pool
			// TODO: do this using getShortestIntegerPush?
			getShortestIntegerPush(cpg, Integer.parseInt(val), il);
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			/* 
			 * pops 2 values from the stack, subtracts the
			 * first from the second and stores the result
			 * on the stack
			 */
			il.append(new ISUB());
			// Store int into local variable
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
			
			System.out.printf("int %s =  (int )%s - (%s)%s;\n", regto, regfrom,
					type, val);
		}
		/** added by IG **/
		else if(opname.equals("sub-int/lit8")) {			
			// sub-int/lit8 - Calculates vy - lit8 and stores the result into vx. 
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			String type = ops[3].replaceAll(",", "");
			String val = ops[4].replaceAll(",", "");
			// Load int from local variable
			il.append(new ILOAD(locals.didx2jvmidxstr(regfrom)));
			// Push item from runtime constant pool
			getShortestIntegerPush(cpg, Integer.parseInt(val), il);
			// il.append(new LDC(cpg.addInteger(Integer.parseInt(val))));
			/* 
			 * pops 2 values from the stack, subtracts the
			 * first from the second and stores the result
			 * on the stack
			 */
			il.append(new ISUB());
			// Store int into local variable
			il.append(new ISTORE(locals.didx2jvmidxstr(regto)));
			
			System.out.printf("int %s =  (int )%s - (%s)%s;\n", regto, regfrom,
					type, val);
		}
		
		//move-wide 
		
		
		/** added by IG **/
		else if (opname.equals("sget-byte")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("byte %s = (byte)%s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new GETSTATIC(thefield));
			il.append(new ISTORE(thereg));

		} 
		/** added by IG **/
		else if (opname.equals("sget-short")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("short %s = (short)%s;\n", regfrom, field);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new GETSTATIC(thefield));
			il.append(new ISTORE(thereg));
			
		}
		/** added by IG **/
		else if (opname.equals("sput-short")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ILOAD(thereg));
			il.append(new PUTSTATIC(thefield));
			System.out.printf("short %s = (short) %s;\n", field, regfrom);
			
		}
		/** added by IG **/
		else if (opname.equals("sput-byte")) {
			String regfrom = ops[1].replaceAll(",", "");
			String field = ops[2].replaceAll(",", "");
			System.out.printf("%s = %s;\n", field, regfrom);
			int thereg = locals.didx2jvmidxstr(regfrom);
			int thefield = geteasyFieldRef(cpg, field);
			il.append(new ILOAD(thereg));
			il.append(new PUTSTATIC(thefield));
			System.out.printf("byte %s = (byte) %s;\n", field, regfrom);
			
		}
		/** added by IG **/
		else if (opname.equals("ushr-long/2addr")) {
			/* 
			 * ushr-long/2addr vx, vy
			 * Unsigned shifts right the value in vx,vx+1 by the positions
			 * specified by vy and stores the result in vx,vx+1.
			 */
			String regto = ops[1].replaceAll(",", "");
			String regfrom = ops[2].replaceAll(",", "");
			System.out.printf("long %s =  (long)%s >> (long)%s;\n", regto,
					regto, regfrom);
			// Pushes long local variable onto the stack
			il.append(new LLOAD(locals.didx2jvmidxstr(regto)));
			il.append(new LLOAD(locals.didx2jvmidxstr(regfrom)));
			/*
			 *  Logical shift right long:
			 *  v2 = int (from stack)
			 *  v1 = long (from stack)
			 *  Pops v2 (4 byte) and then v1 (8 byte) from the
			 *  operand stack, shits v1 right by the low 6 bits
			 *  of v2 and pushes the result onto the stack.
			 *  
			 */
			// changed LSHR -> LUSHR
			il.append(new LUSHR());
			// store long variable on the top of the stack into regto
			il.append(new LSTORE(locals.didx2jvmidxstr(regto)));
			
		}
		
		/* TODO: check if the following operations work.
		 * All I did was take the quick operation and handle
		 * it the same way the "slow" operation is handled.
		 */

		/** added by IG **/
		else if (opname.equals("iput-wide-quick")) {
			handle_iput_wide(ops, il, cpg, locals);
		}
		
		/** added by IG **/
		else if (opname.equals("iput-quick")) {
			handle_iput(ops, il, cpg, locals);
		}
		
		/** added by IG **/
		else if (opname.equals("iget-wide-quick")) {
			handle_iget_wide(ops, il, cpg, locals);
		}
		
		/** added by IG **/
		else if (opname.equals("iget-quick")) {
			handle_iget(ops, il, cpg, locals);
		}
		
		else {
			// jlog.info("unknown");
			// added by max 6/23 to print a stack trace but do not exit
			
			// Utils.stopAndDump("Unknown Opcode:*" + opname + "*");
			Utils.continueAndDump("Unknown Opcode:*" + opname + "*");
		}

		String y_il = il.toString(true);
		if (y_il.equals(z_il)) {
			jlog.info("Ende: " + y_il);
			Utils.stopAndDump("no more bytecodes appended:" + opname);
		}
		// jlog.info("BC: " + y_il);

		return il;
	}

	private static void logfmtstr3(String regres, String regadd1, String regadd2,
			String fmt) {
		StringBuilder sb = new StringBuilder();
		Formatter f = new Formatter(sb, Locale.US);
		f.format(fmt, regres, regadd1, regadd2);
		jlog.info(sb.toString());
	}

	private static void loginteger(String regres, int i) {
		StringBuilder sb = new StringBuilder();
		jlog.info(regres+i);
	}

	
	private void handle_const4(DalvikCodeLine dcl, ConstantPoolGen cpg,
			LocalVarContext locals, InstructionList il, String[] ops) {
		String reg = ops[1].replaceAll(",", "");
		String type = ops[2].replaceAll("#", "");
		int val = Integer.parseInt(ops[3]);
		System.out.printf("(%s) %s = %s;\n", type, reg, val);

		String nextopname = dcl.getNext().getOpname();

		jlog.info(nextopname);
		InstructionList il2 = new InstructionList();

		boolean strategy1 = false;
		boolean strategy2 = !strategy1;

		if (val != 0) {
			if (type.equals("int")) {
				getShortestIntegerPush(cpg, val, il2);
				il2.append(new ISTORE(locals.didx2jvmidxstr(reg)));
				il.append(il2);
				return;
			} else {
				Utils.stopAndDump("const4 branch unhandled!");
			}
		} else

		/*
		 * if (strategy1) { if (type.equals("int")) {
		 * getShortestIntegerPush(cpg, val, il2); il2.append(new
		 * ISTORE(locals.didx2jvmidxstr(reg))); } else { il2.append(new
		 * ACONST_NULL()); il2.append(new ASTORE(locals.didx2jvmidxstr(reg)));
		 * 
		 * } } else
		 * 
		 * if (strategy2)
		 */{

			jlog.info("List2:"+il2);
			// if (!type.equals("int"))
			// Utils.stopAndDump("over:" + type + ":" + val);
			// if (false) {
			DalvikCodeLine lauf = dcl;
			String mtype = "";
			for (; lauf != null; lauf = lauf.getNext()) {
				String curop = lauf._opname;
				if (curop.equals("move-result-object")
						|| curop.equals("iput-object")
						|| curop.equals("aget-object") || curop.equals("move")) {
					jlog.info(Arrays.toString(lauf._ops));
					jlog.info(Arrays.toString(lauf._regs));
					String mreg = "";
					if (curop.equals("move")) {
						mreg = lauf._ops[2];
					} else if (curop.equals("aget-object")) {
						mreg = lauf._ops[3];
					} else
						mreg = lauf._ops[1];

					// Utils.stopAndDump("xxx");
					if (mreg.equals(reg)) {
						if (curop.contains("object")
								&& !curop.equals("aget-object")) {
							mtype = "object";
						} else {
							mtype = "";
						}
						jlog.info(mreg + ":" + reg + ":" + lauf);
						lauf = null;
						break;
					}
				}
			}

			if (mtype.equals("object")
					|| (val == 0 && (nextopname.endsWith("put-object") || nextopname
							.endsWith("check-cast")))) {
				il2.append(new ACONST_NULL());
				il2.append(new ASTORE(locals.didx2jvmidxstr(reg)));

			} else {
				getShortestIntegerPush(cpg, val, il2);
				il2.append(new ISTORE(locals.didx2jvmidxstr(reg)));
				jlog.info("List2:"+il2);

			}
		}

		il.append(il2);
		// Utils.stopAndDump("wuff,hier:" + il2);
	}

	private static void getShortestIntegerPush(ConstantPoolGen cpg, int val,
			InstructionList il2) {
		jlog.log(Level.INFO, "val=" + val);
		if (val >= -1 && val <= 5) {
			il2.append(new ICONST(val));
		} else {
			il2.append(new LDC(cpg.addInteger(val)));
		}
		jlog.log(Level.INFO, "il2=" + il2);

	}

	private static void handle_invoke_direct(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext locals) {
		// String reg = ops[1].replaceAll(",", "");
		String classandmethod = ops[2].replaceAll(",", "");
		// System.out.printf("(%s)-> %s ;\n", reg, classandmethod);
		// il.append(new ALOAD(locals.didx2jvmidxstr(regs[0])));
		// VarType vt = VarType.PARAM;
		String[] classmethod = extractClassAndMethod(classandmethod);
		int metref = cpg.addMethodref(Utils.toJavaName(classmethod[0]),
				classmethod[1], classmethod[2]);
		genParameterByRegs(il, locals, regs, classmethod, cpg, metref, true);

		il.append(new INVOKESPECIAL(metref));
		// jlog.info(il.toString(true));
	}

	private static int geteasyFieldRef(ConstantPoolGen cpg, String field) {
		String theclass = field.split("\\.")[0];
		String thefieldname = field.split("\\.")[1].split(":")[0];
		String thetype = field.split("\\.")[1].split(":")[1].split(" ")[0];
		int cpref = cpg.addFieldref(Utils.toJavaName(theclass), thefieldname,
				thetype);
		return cpref;
	}

	private static Type getTypeForField(ConstantPoolGen cpg, String field) {
		String theType = field.split("\\.")[1].split(":")[1].split(" ")[0];
		return Type.getType(theType);
	}

	/*
	 * private static void dumpRegs(LocalVarContext locals) { for
	 * (Iterator<String> e = locals.getlocals().keySet().iterator(); e
	 * .hasNext();) { String z = e.next(); jlog.info(z);
	 * jlog.info(locals.getlocals().get(z).getName()); } }
	 */

	/*
	 * private static String[] extractClassAndMethod_OLD(String classandmethod)
	 * { String[] classmethod = classandmethod.split("[\\;\\: ]");
	 * classmethod[0] = classmethod[0] + ";"; classmethod[1] =
	 * classmethod[1].substring(1); if (classmethod[2].startsWith("L")) {
	 * classmethod[2] += ";"; } // classmethod[2] = classmethod[1].substring(1);
	 * 
	 * jlog.info("0:" + classmethod[0]); jlog.info("1:" +
	 * classmethod[1]); jlog.info("2:" + classmethod[2]); return
	 * classmethod; }
	 */

	static String[] extractClassAndMethod(String classandmethod) {
		String[] comps = classandmethod.split("\\.");
		String theclass = comps[0];
		String thefieldname = comps[1].split(":")[0];
		String thetype = comps[1].split(":")[1].split(" ")[0];
		return new String[] { theclass, thefieldname, thetype };
	}

	/*
	 * private static Hashtable<String, String> extractClassAndMethodHash(
	 * String classandmethod) { String[] x =
	 * extractClassAndMethod(classandmethod); Hashtable<String, String> ht = new
	 * Hashtable<String, String>(); ht.put("class", x[0]); ht.put("method",
	 * x[1]); ht.put("sig", x[2]); return ht; }
	 */

	private static void handle_new_array(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String vx = ops[1].replaceAll(",", "");

		String size = ops[2].replaceAll(",", "");
		String type = ops[3].replaceAll(",", "");
		il.append(new ILOAD((short) lvg.didx2jvmidxstr(size)));
		if (type.substring(1).startsWith("L")
				|| type.substring(1).startsWith("[")) {
			il.append(new ANEWARRAY(Utils.doAddClass(cpg, type.substring(1))));
		} else

		{
			il
					.append(new NEWARRAY((BasicType) Type.getType(type
							.substring(1))));
		}
		il.append(new ASTORE(lvg.didx2jvmidxstr(vx)));

		// jlog.log(Level.INFO, "char {$0} := {$1}[{$2}]  ;\n", new
		// Object[]{regdest, regarr, regfrom});

		jlog.log(Level.INFO, "{$0} = new {$1}[{$2}];\n", new Object[] { vx,
				type, size });
	}

	private static void handle_new_instance(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String vx = ops[1].replaceAll(",", "");
		String type = ops[2].replaceAll(",", "");

		il.append(new NEW(Utils.doAddClass(cpg, type)));
		il.append(new ASTORE(lvg.didx2jvmidxstr(vx)));
		System.out.printf("%s = new %s();\n", vx, type);
		lvg.annotateLV(vx, type);
	}

	private static void handle_move_result(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg, OpcodeSequence oc,
			DalvikCodeLine dcl) {
		String regoper = ops[1].replaceAll(",", "");
		jlog.info(regoper + " := res ;\n");
		DalvikCodeLine nextInstr = dcl.getPrev();
		String nextop = nextInstr._opname;
		if (!(nextInstr._opname.startsWith("invoke"))
				&& !(nextInstr._opname.startsWith("+invoke"))
				&& !(nextInstr._opname.startsWith("+execute-inline"))) {
			Utils.stopAndDump("no prev invoke:" + nextInstr._opname);

		}
		if (nextop.startsWith("invoke")) {
			String classandmethod = nextInstr._ops[2].replaceAll(",", "");
			jlog.info(Arrays.toString(nextInstr._ops) + ":" + classandmethod);
			// TODO IBC => istore mapper
			if (classandmethod.endsWith(")I") || classandmethod.endsWith(")Z")
					|| classandmethod.endsWith(")B")
					|| classandmethod.endsWith(")C")
					|| classandmethod.endsWith(")S")) {
				il.append(new ISTORE(lvg.didx2jvmidxstr(regoper)));
			} else if (classandmethod.endsWith(")F")) {
				il.append(new FSTORE(lvg.didx2jvmidxstr(regoper)));
			} else
				Utils.stopAndDump("unknown type" + classandmethod);
		} else if (nextop.startsWith("+invoke")) {
			int vtableidx = OpCodeHandler_ODEX.getvtableidx(nextInstr._ops);
			// int vtableidx = 14;
			String thetype = lvg.getLV(regoper).getType();
			jlog.info("reg:" + regoper);
			jlog.info("type:" + thetype);
			jlog.info("idx:" + vtableidx);
			DexMethodDetails dmd = DalvikToJVM.cc.getVTableEntryForClass(
					thetype, vtableidx);
			jlog.info(dmd.toString());
			String classandmethod = dmd.getClassName() + dmd.getName()
					+ dmd.getSig();

			jlog.info(classandmethod);
			// String a[] = extractClassAndMethod(classandmethod);
			if (classandmethod.endsWith(")I") || classandmethod.endsWith(")Z")
					|| classandmethod.endsWith(")C")
					|| classandmethod.endsWith(")S")) {
				il.append(new ISTORE(lvg.didx2jvmidxstr(regoper)));
			} else if (classandmethod.endsWith(")F")) {
				il.append(new FSTORE(lvg.didx2jvmidxstr(regoper)));
			} else
				Utils.stopAndDump("unknown type" + classandmethod);
		} else if (nextop.startsWith("+execute")) {
			// int vtableidx = OpCodeHandler_ODEX.getvtableidx(nextInstr._ops);
			il.append(new ISTORE(lvg.didx2jvmidxstr(regoper)));
		}

		// Utils.stopAndDump("branch ok");

		else {
			Utils.stopAndDump("should not reach here");
		}

	}

	private static void handle_move_result_wide(String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {
		String regoper = ops[1].replaceAll(",", "");
		jlog.info(regoper + " := res ;\n");
		DalvikCodeLine nextInstr = dcl.getPrev();
		if (!(nextInstr._opname.startsWith("invoke"))) {
			Utils.stopAndDump("no prev invoke:" + nextInstr._opname);

		}
		/* TODO ggf. auch Double? */
		String classandmethod = nextInstr._ops[2].replaceAll(",", "");
		jlog.info(Arrays.toString(nextInstr._ops) + ":" + classandmethod);
		if (classandmethod.endsWith(")J")) {
			il.append(new LSTORE(lvg.didx2jvmidxstr(regoper)));
		} else if (classandmethod.endsWith(")D")) {
			il.append(new DSTORE(lvg.didx2jvmidxstr(regoper)));
		} else
			Utils.stopAndDump("unknown type");
	}

	private static void handle_move_result_object(String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		jlog.info(regoper + " := res ;\n");
		il.append(new ASTORE(lvg.didx2jvmidxstr(regoper)));
	}

	private static void handle_move_exception(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		il.append(new ASTORE(lvg.didx2jvmidxstr(regoper)));
		jlog.info("Exception " + regoper + ":= res ;\n");
	}

	private static void handle_throw_exception(String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		il.append(new ALOAD(lvg.didx2jvmidxstr(regoper)));
		il.append(new ATHROW());
		jlog.info("throw " + regoper + " %s  ;\n");

	}

	private static void handle_invoke_direct_range(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg) {
		// String reg = ops[1].replaceAll(",","");
		// String classandmethod = ops[2].replaceAll(",", "");
		String params = getparams(regs);

		// String reg = ops[1].replaceAll(",", "");
		String classandmethod = ops[2].replaceAll(",", "");
		String[] a = extractClassAndMethod(classandmethod);
		int methref = cpg.addMethodref(Utils.toJavaName(a[0]), a[1], a[2]);
		// VarType vthis = VarType.THIS;
		// genParameterLoad(il, lvg, vthis);
		// VarType vt = VarType.PARAM;
		// genParameterLoad(il, lvg, vt);

		genParameterByRegs(il, lvg, regs, a, cpg, methref, true);

		il.append(new INVOKEVIRTUAL(methref));

		if (!classandmethod.endsWith(")V")) {
			jlog.info("res = ");
		}
		jlog.log(Level.INFO, "{0}-> {1}({2}) ;\n", new Object[] { regs[0],
				classandmethod, params });
	}

	public static void handle_invoke_static(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {
		// String reg = ops[1].replaceAll(",", "");
		String classandmethod = ops[2].replaceAll(",", "");
		String[] a = extractClassAndMethod(classandmethod);
		int methref = cpg.addMethodref(Utils.toJavaName(a[0]), a[1], a[2]);
		jlog.info("methodref=" + a[0] + ":" + a[1] + ":" + a[2]);
		// VarType vt = VarType.PARAM;
		genParameterByRegs(il, lvg, regs, a, cpg, methref, false);
		il.append(new INVOKESTATIC(methref));

		String param2s = getstaticparams(regs);

		for (int i = 0; i < a.length; i++) {
			jlog.info(i + ":" + a[i]);
		}
		if (!classandmethod.endsWith(")V")) {
			jlog.info("res = ");
		}

		DalvikCodeLine nextInstr = dcl.getNext();

		if (!nextInstr._opname.startsWith("move-result")
				&& !classandmethod.endsWith(")V")) {
			if (classandmethod.endsWith(")J") || classandmethod.endsWith(")D")) {
				il.append(new POP2());
			} else {
				il.append(new POP());
			}
		}

		jlog.log(Level.INFO, " {0} ({1}) ;\n", new Object[] { classandmethod,
				param2s });
		// stopAndDump("temp");
	}

	/*
	 * private static void genParameterLoad(InstructionList il, LocalVarContext
	 * lvg, VarType vt) { Hashtable<String, LocalVar> params =
	 * lvg.getLVsByType(vt);
	 * 
	 * for (Enumeration<String> e = params.keys(); e.hasMoreElements();) {
	 * LocalVar lv = lvg.getlocals().get(e.nextElement()); il.append(new
	 * ALOAD(lv.getjvmidex())); } }
	 */

	public static void genParameterByRegs(InstructionList il,
			LocalVarContext lvg, String regs[], String params[],
			ConstantPoolGen cpg, int x, boolean isdynamic) {

		String sig = params[2];

		/* Parameterleiste auswerten und Typen zuweisen ! */

		Type[] t = Type.getArgumentTypes(sig);
		if (t.length == 0 && !isdynamic) {
			return;
		}
		// if (t.length == 0 && isdynamic) {
		// String _thereg = regs[0];
		// LocalVar lv = lvg.getLV(_thereg);
		// il.append(new ALOAD(lv.getjvmidex() ));
		// il.append(new ALOAD(0));
		// return;
		// }

		// if (t.length==0 && isdynamic) {
		// return;
		// }
		jlog.info("dynamic=" + isdynamic);

		jlog.info("sig=" + sig);
		jlog.info("types=" + Arrays.toString(t));
		// int j = 0;
		boolean onerun = false;
		int numreg = 0;
		jlog.info(Arrays.toString(regs));
		for (int j = 0; j < regs.length; j++) {
			String _thereg = regs[j];
			jlog.info("thereg=" + _thereg);
			jlog.info(Arrays.toString(lvg.getlocals().keySet().toArray()));
			LocalVar lv = lvg.getLV(_thereg);
			jlog.info("thevar=" + lv.getName());

			if (j == 0 && isdynamic && !onerun) {
				il.append(new ALOAD(lv.getjvmidex()));
				jlog.info("t=this");
				onerun = true;

			} else {
				jlog.info("t=" + j);
				int nrreg = numreg;
				// if (isdynamic) {
				// nrreg -= 1;
				// }
				// else {
				if (numreg >= t.length) {
					break;
				}
				// }
				Instruction instr = LocalVarContext.getLoadStoreInstructionFor(
						true, t[nrreg], lv.getjvmidex());
				jlog.info("t[j]" + t[nrreg]);
				il.append(instr);
				// j++;
				if (instr instanceof DLOAD || instr instanceof LLOAD) {
					j++;
				}
				numreg++;
				// if (j>= regs.length) {
				// break;
				// }

			}
		}
		// if (t.length > 2) {
		// jlog.info(il);
		// Utils.stopAndDump("by genparam:" + sig);
		// }
		// Hashtable<String, LocalVar> params = ;
		//
		// for (Enumeration<String> e = params.keys(); e.hasMoreElements();) {
		// LocalVar lv = lvg.ht.get(e.nextElement());
		// il.append(new ALOAD(lv.jvmidx));
		// }
	}

	// private static void handle_invoke_static_range(String[] regs, String[]
	// ops) {
	// // String reg = ops[1].replaceAll(",", "");
	//
	// String classandmethod = ops[2].replaceAll(",", "");
	// String params = getstaticparams(regs);
	//
	// if (!classandmethod.endsWith(")V"))
	// System.out.print("res = ");
	// System.out.printf(" %s (%s) ;\n", classandmethod, params);
	// // System.exit(1);
	// }

	private static void handle_invoke_virtual_direct(String[] regs, String[] ops) {
		String classandmethod = ops[2].replaceAll(",", "");
		String params = getparams(regs);
		if (!classandmethod.endsWith(")V"))
			jlog.info("res = ");
		jlog.log(Level.INFO, "(${0})-> %{1} ({2}) ;\n", new Object[] { regs[0],
				classandmethod, params });
	}

	private static void handle_invoke_interface(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg) {
		String classandmethod = ops[2].replaceAll(",", "");
		String params = getparams(regs);
		String a[] = extractClassAndMethod(classandmethod);

		if (!classandmethod.endsWith(")V"))
			jlog.info("res = ");
		jlog.log(Level.INFO, "(%s)-> %s (%s) ;\n", new Object[] { regs[0],
				classandmethod, params });

		int metref = cpg.addInterfaceMethodref(Utils.toJavaName(a[0]), a[1],
				a[2]);
		genParameterByRegs(il, lvg, regs, a, cpg, metref, true);

		il.append(new INVOKEINTERFACE(metref, regs.length));
	}

	private static void handle_invoke_super(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg) {
		String classandmethod = ops[2].replaceAll(",", "");
		String params = getparams(regs);
		String a[] = extractClassAndMethod(classandmethod);

		if (!classandmethod.endsWith(")V"))
			jlog.info("res = ");

		jlog.log(Level.INFO, "(%s)-> %s (%s) ;\n", new Object[] { regs[0],
				classandmethod, params });

		int metref = cpg.addMethodref(Utils.toJavaName(a[0]), a[1], a[2]);
		genParameterByRegs(il, lvg, regs, a, cpg, metref, true);

		il.append(new INVOKESPECIAL(metref));
	}

	private static void handle_invoke_virtual(String[] regs, String[] ops,
			InstructionList il, ConstantPoolGen cpg, LocalVarContext lvg,
			OpcodeSequence oc, DalvikCodeLine dcl) {
		// String reg = ops[1].replaceAll(",","");
		String classandmethod = ops[2].replaceAll(",", "");
		String params = getparams(regs);
		String a[] = extractClassAndMethod(classandmethod);

		if (!classandmethod.endsWith(")V"))
			jlog.info("res = ");

		jlog.log(Level.INFO, "(%s)-> %s (%s) ;\n", new Object[] { regs[0],
				classandmethod, params });
		// il.append(new ALOAD(lvg.didx2jvmidxstr(regs[0])));

		// il.append(new INVOKEVIRTUAL(cpg.addMethodref(theclass, thefieldname,
		// thetype)));
		// VarType vthis = VarType.THIS;
		// genParameterLoad(il, lvg, vthis);
		// il.append(new ALOAD(lvg.didx2jvmidxstr(regs[0])));
		int metref = cpg.addMethodref(Utils.toJavaName(a[0]), a[1], a[2]);
		genParameterByRegs(il, lvg, regs, a, cpg, metref, true);
		il.append(new INVOKEVIRTUAL(metref));
		DalvikCodeLine nextInstr = dcl.getNext();

		if (!nextInstr._opname.startsWith("move-result")
				&& !classandmethod.endsWith(")V")) {
			if (classandmethod.endsWith(")J") || classandmethod.endsWith(")D")) {
				il.append(new POP2());
			} else {
				il.append(new POP());
			}
		}

	}

	private static void handle_iget(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		// System.out.printf("%s := (%s)-> %s ;\n", regdest, regclass, dest);
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });
		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		String iref = Utils.toJavaName(classmethod[0]);
		jlog.info(iref);
		// Utils.stopAndDump("ende");
		il.append(new GETFIELD(cpg.addFieldref(iref, classmethod[1],
				classmethod[2])));
		il.append(new ISTORE(jvmdest));

	}

	private static void handle_iget_wide(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });
		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		String iref = Utils.toJavaName(classmethod[0]);
		jlog.info(iref);
		// Utils.stopAndDump("ende");
		il.append(new GETFIELD(cpg.addFieldref(iref, classmethod[1],
				classmethod[2])));
		if (ops[3].endsWith(":J")) {
			il.append(new LSTORE(jvmdest));
		} else if (ops[3].endsWith(":D")) {
			il.append(new DSTORE(jvmdest));
		} else {
			Utils.stopAndDump("what's this");
		}

		// il.append(new ISTORE(jvmdest));

	}

	private static void handle_iget_object(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });

		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new GETFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		il.append(new ASTORE(jvmdest));
	}

	private static void handle_iget_boolean(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });

		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new GETFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		il.append(new ISTORE(jvmdest));

	}

	private static void handle_iget_short(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });

		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new GETFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		il.append(new ISTORE(jvmdest));

	}

	private static void handle_iget_byte(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });

		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new GETFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		il.append(new ISTORE(jvmdest));
	}

	private static void handle_iget_char(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regclass = ops[2].replaceAll(",", "");

		int jvmdest = lvg.didx2jvmidxstr(regdest);
		int jvmclass = lvg.didx2jvmidxstr(regclass);

		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "%s := (%s)-> %s ;\n", new Object[] { regdest,
				regclass, dest });

		il.append(new ALOAD(jvmclass));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new GETFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		il.append(new ISTORE(jvmdest));

	}

	private static void handle_iput(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		/*
		 * Puts vx into an instance field. The instance is referenced by vy.
		 */String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");

		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ILOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
	}

	private static void handle_iput_wide(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		/*
		 * Puts vx into an instance field. The instance is referenced by vy.
		 */

		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");

		jlog.info(Arrays.toString(ops));
		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		if (ops[3].endsWith(":J")) {
			il.append(new LLOAD(lvg.didx2jvmidxstr(regoper)));
		} else if (ops[3].endsWith(":D")) {
			il.append(new DLOAD(lvg.didx2jvmidxstr(regoper)));
		} else {
			Utils.stopAndDump("what's this");
		}
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));

	}

	private static void handle_iput_boolean(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");

		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ILOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
	}

	private static void handle_iput_short(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");
		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ILOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
	}

	private static void handle_iput_byte(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");
		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ILOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
	}

	private static void handle_iput_char(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");
		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ILOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
	}

	private static void handle_iput_object(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regoper = ops[1].replaceAll(",", "");
		String regdest = ops[2].replaceAll(",", "");
		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "(%s)-> %s := %s ;\n", new Object[] { regdest,
				dest, regoper });

		il.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il.append(new ALOAD(lvg.didx2jvmidxstr(regoper)));
		String[] classmethod = extractClassAndMethod(dest);
		il.append(new PUTFIELD(cpg.addFieldref(
				Utils.toJavaName(classmethod[0]), classmethod[1],
				classmethod[2])));
		// il.append(new PUTFIELD(cpref));
	}

	private static void handle_aput(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		/*
		 * aput vx,vy,vz puts the integer value in vx into an element of an
		 * integer array. The element is indexed by vz, the array object is
		 * referenced by vy.
		 */
		String regfrom = ops[1].replaceAll(",", ""); // vx

		String regto = ops[2].replaceAll(",", ""); // vy

		String regidx = ops[3].replaceAll(",", ""); // vz

		jlog.log(Level.INFO, "{$0}[{$1}] := {$2} ;\n", new Object[] { regto,
				regidx, regfrom });

		// System.out.printf("%s[%s] := %s ;\n", regto, regidx, regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regto)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regidx)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new IASTORE());
		il.append(il2);

	}

	private static void handle_aput_boolean(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0}[{$1}] := boolean {$2} ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("%s[%s] := (boolean) %s    ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regdest)));
		il2.append(new BASTORE());
		il.append(il2);
		// jlog.info(il);
		// Utils.stopAndDump("testing");

	}

	private static void handle_aput_char(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0}[{$1}] := (char) {$2} ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("%s[%s] := (char) %s    ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regdest)));
		il2.append(new CASTORE());
		il.append(il2);
		// jlog.info(il);
		// Utils.stopAndDump("testing");

	}

	private static void handle_aput_short(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0}[{$1}] := (short) {$2} ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("%s[%s] := (char) %s    ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regdest)));
		il2.append(new SASTORE());
		il.append(il2);
		// jlog.info(il);
		// Utils.stopAndDump("testing");

	}

	private static void handle_aput_byte(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0}[{$1}] := (byte) {$2} ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("%s[%s] := (byte) %s    ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regdest)));
		il2.append(new BASTORE());
		il.append(il2);
		// jlog.info(il);
		// Utils.stopAndDump("testing");

	}

	private static void handle_aput_object(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		// String regoper = ops[1].replaceAll(",", "");
		// String regclass = ops[2].replaceAll(",", "");

		// String dest = ops[3].replaceAll(",", "");
		InstructionList il2 = new InstructionList();
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regdest)));
		il2.append(new AASTORE());
		il.append(il2);

		jlog.log(Level.INFO, "{$0}[{$1}] := (object) {$2} ;\n", new Object[] {
				regdest, regarr, regfrom });
		/* is this ok? */

		// System.out
		// .printf("%s[%s] := (object )%s ;\n", regarr, regfrom, regdest);

	}

	private static void handle_array_length(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regto = ops[1].replaceAll(",", "");
		String regoper = ops[2].replaceAll(",", "");

		// String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0} := {$1}.length  ;\n", new Object[] { regto,
				regoper });

		// System.out.printf("%s := %s.length  ;\n", regto, regoper);
		il.append(new ALOAD(lvg.didx2jvmidxstr(regoper)));
		il.append(new ARRAYLENGTH());
		il.append(new ISTORE(lvg.didx2jvmidxstr(regto)));

		// System.exit(0);
	}

	private static void handle_aget(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "{$0} := {$1}[{$2}]  ;\n", new Object[] { regdest,
				regarr, regfrom });

		// System.out.printf(" %s := %s[%s]  ;\n", regdest, regarr, regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new IALOAD());
		il2.append(new ISTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);
		// jlog.info(il);
		// Utils.stopAndDump("testing");

	}

	private static void handle_aget_boolean(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "boolean {$0} := {$1}[{$2}]  ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out
		// .printf("boolean %s := %s[%s]  ;\n", regdest, regarr, regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new BALOAD());
		il2.append(new ISTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);

	}

	private static void handle_aget_byte(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");
		jlog.log(Level.INFO, "byte {$0} := {$1}[{$2}]  ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("byte %s := %s[%s]  ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new BALOAD());
		il2.append(new ISTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);

	}

	private static void handle_aget_short(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "short {$0} := {$1}[{$2}]  ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("byte %s := %s[%s]  ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new SALOAD());
		il2.append(new ISTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);

	}

	private static void handle_aget_char(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {
		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "char {$0} := {$1}[{$2}]  ;\n", new Object[] {
				regdest, regarr, regfrom });

		// System.out.printf("byte %s := %s[%s]  ;\n", regdest, regarr,
		// regfrom);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new CALOAD());
		il2.append(new ISTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);

	}

	/* @TODO: jvmregs */
	private static void handle_aget_object(String[] ops, InstructionList il,
			ConstantPoolGen cpg, LocalVarContext lvg) {

		String regdest = ops[1].replaceAll(",", "");
		String regarr = ops[2].replaceAll(",", "");
		String regfrom = ops[3].replaceAll(",", "");

		String dest = ops[3].replaceAll(",", "");

		jlog.log(Level.INFO, "object {$0} := {$1}[{$2}]  ;\n", new Object[] {
				regdest, regarr, dest });

		// System.out.printf("object %s := %s[%s]  ;\n", regdest, regarr, dest);
		InstructionList il2 = new InstructionList();
		il2.append(new ALOAD(lvg.didx2jvmidxstr(regarr)));
		il2.append(new ILOAD(lvg.didx2jvmidxstr(regfrom)));
		il2.append(new AALOAD());
		il2.append(new ASTORE(lvg.didx2jvmidxstr(regdest)));
		il.append(il2);
		// jlog.info(il);

	}

}
