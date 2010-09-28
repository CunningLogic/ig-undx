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

package org.illegalaccess.undx;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.bcel.generic.ArrayType;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.ObjectType;
import org.apache.bcel.generic.Type;

public class Utils {

	private static Logger jlog = Logger.getLogger(Utils.class.getName());

	public static String sprintf(String formatString, Object[] objs) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream f = new PrintStream(baos);
		f.printf(formatString, objs);
		String z = baos.toString();
		return z;
	}

	String getFromFile(String z) throws FileNotFoundException, IOException {
		FileInputStream fis = new FileInputStream(z);

		int f = fis.available();

		byte[] b = new byte[f];

		int k = fis.read(b);
		fis.close();
		if (k != f) {
			Utils.stopAndDump("input too short");
		}
		fis.close();
		String contents = new String(b);
		return contents;
	}

	static int b2i(byte b) {
		int x = b;

		if (b < 0) {
			x = 256 + b;
		}
		return x;
	}

	/* Random convertion utils, etc. */
	static int intFrombytes(byte[] b, int pos) {
		// System.out.println(Arrays.toString(b)+":"+pos);
		return b2i(b[pos]) + b2i(b[pos + 1]) * 256 + b2i(b[pos + 2]) * 65536
				+ b2i(b[pos + 3]) * 65536 * 256;

	}

	public static long longFrombytes(byte[] b, int pos) {
		// System.out.println(Arrays.toString(b)+":"+pos);
//		long a = b2i(b[pos]) + b2i(b[pos + 1]) * 256 + b2i(b[pos + 2]) * 65536
//				+ b2i(b[pos + 3]) * 65536 * 256;
		long c = b2i(b[pos + 4]) + b2i(b[pos + 5]) * 256 + b2i(b[pos + 6])
				* 65536 + b2i(b[pos + 7]) * 65536 * 256;
		c = c << 16;
		return c;
	}

	public static int shortFrombytes(byte[] b, int pos) {
		return b2i(b[pos]) + b2i(b[pos + 1]) * 256;

	}

	public static int swapInt(int i) {
		int a = i % 256;
		int b = i / 256;
		return a * 256 + b;
	}

	public static void stopAndDump(String reason) {
		new Throwable().printStackTrace();
		System.err.println("exited because of:" + reason);
		System.exit(-1);
	}

	public static void continueAndDump(String reason) {
		new Throwable().printStackTrace();
		System.err.println("exited because of:" + reason);
		// System.exit(-1);
	}

	public static String toJavaName(String vmname) {

		if (vmname.equals("[B"))
			return vmname;
		if (vmname.equals("[S"))
			return vmname;
		if (vmname.equals("[C"))
			return vmname;
		if (vmname.equals("[[I"))
			return vmname;
		if (vmname.equals("[I"))
			return vmname;
		if (!vmname.endsWith(";")) {
			Utils.stopAndDump("not a vmname:" + vmname);
		}

		if (vmname.startsWith("L")) {
			vmname = vmname.substring(1);
		}

		return vmname.replace('/', '.').replaceAll(";", "");
	}

	public static String toVMname(String javaname) {
		return "L" + javaname.replace('.', '/') + ";";
	}

	public static int doAddClass(ConstantPoolGen cpg, String type) {
		jlog.log(Level.INFO, "Type=" + type);
		// type = toJavaName(type);
		jlog.log(Level.INFO, "Type=" + type);
		Type t = ObjectType.getType(type);
		jlog.log(Level.INFO, "t=" + t);
		int val = 0;
		if (t instanceof ArrayType) {
			val = cpg.addArrayClass((ArrayType) t);
		} else {
			val = cpg.addClass((ObjectType) t);
		}
		return val;
	}

	public static String getFourCharHexString(int destaddr) {
		String str_dest = Integer.toHexString(destaddr);
		if (destaddr < 0) {
			str_dest = str_dest.substring(str_dest.length() - 4);
		} else if (destaddr < 16) {
			str_dest = "000" + str_dest;
		} else if (destaddr < 256) {
			str_dest = "00" + str_dest;
		} else if (destaddr < 4096) {
			str_dest = "0" + str_dest;
		}
		return str_dest;
	}

	static void writeBytebufferToFile(String destdump, byte[] bytes)
			throws FileNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(destdump);
		fos.write(bytes);
		fos.close();
	}

}
