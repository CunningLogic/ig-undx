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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Logger;
import java.util.zip.ZipException;

public class APKAccess {

	private boolean debug = false;

	private static Logger jlog = Logger.getLogger(APKAccess.class.getName());
	byte[] dexbuffer = new byte[0];
	String theFileName = "";
	String adkloc;
	StringBuffer res;
	ArrayList<String> conststr;

	String getString(int i) {
		return conststr.get(i);
	}

	public static APKAccess fromFile(File f) throws IOException {
		APKAccess a = new APKAccess(f.getAbsolutePath());
		return a;
	}

	public APKAccess(String file) throws IOException {

		conststr = new ArrayList<String>();
		adkloc = DalvikToJVM.askloc;

		theFileName = file;
		if (adkloc.length() > 0) {
			if( adkloc.charAt( adkloc.length()-1 ) != File.separatorChar )
			adkloc += File.separatorChar;
		}
		
		Process p = Runtime.getRuntime().exec(
				new String[] { adkloc + "tools" + "/dexdump", "-dfh",
						theFileName });
		BufferedReader is = new BufferedReader(new InputStreamReader(p
				.getInputStream()));
		// ArrayList<String> al = new ArrayList<String>();
		String text = "";
		res = new StringBuffer();
		while ((text = is.readLine()) != null) {
			res.append(text + System.getProperty("line.separator"));
			if (debug) {
				jlog.severe(res.toString());
			}
		}
		if (theFileName.endsWith(".dex") || theFileName.endsWith(".odex")) {
			InputStream fis = new FileInputStream(theFileName);
			int all = fis.available();
			byte b[] = new byte[all];
			jlog.info("avail=" + all);
			int k = fis.read(b);
			fis.close();
			dexbuffer = b;
		} else {
			try {
				dexbuffer = getBytesFromClassesDex(0, -1, true);
			} catch (FileNotFoundException e) {
				throw new FileNotFoundException(e.getMessage() + " in "
						+ theFileName);
			}
		}
		parseConstantPool();
		is.close();

	}

	void parseConstantPool() {
		jlog.fine("Constpool");
		int pos = 0;
		boolean found = false;
		while (!found) {
			int tmp = Utils.intFrombytes(dexbuffer, pos);
			if (tmp == 0x12345678L) {
				found = true;
				break;
			}
			pos = pos + 4;
		}
		// System.out.println(pos);
		// System.out.println("pos:" + pos);
		int numstrings = Utils.intFrombytes(dexbuffer, pos + 16);
		// System.out.println("numstrings:" + numstrings + ":"
		// + Long.toHexString(numstrings));
		int offsetstrings = Utils.intFrombytes(dexbuffer, pos + 20);
		int stroffset = Utils.intFrombytes(dexbuffer, offsetstrings);
		// int pstrlen = Utils.intFrombytes(dexbuffer, offsetstrings + 4);
		// System.out.println("offsetstrings:" + offsetstrings + ":"
		// + Long.toHexString(offsetstrings));
		// System.out.println("stroffset:" + stroffset + ":"
		// + Long.toHexString(stroffset));
		// System.out.println("pstrlen:" + pstrlen + ":"
		// + Long.toHexString(pstrlen));
		pos = stroffset;
		for (int i = 0; i < numstrings; i++) {
			StringBuffer thestr = new StringBuffer();

			int strlen = (char) (dexbuffer[pos]) % 256;
			pos = pos + 1;
			// System.out.println("strlen:" + strlen + ":"
			// + Long.toHexString(strlen));

			for (int j = 0; j < strlen; j++) {
				thestr.append((char) dexbuffer[pos]);
				pos = pos + 1;
			}

			jlog.fine(i + ":" + thestr);
			pos = pos + 1;

			conststr.add(i, thestr.toString());
		}
	}

	public String getDumpFromAPK() throws IOException {

		return res.toString();

	}

	public byte[] getBytesFromClassesDex(int offset, int length)
			throws IOException {
		byte[] bb = getBytesFromClassesDex(offset, length, true);
		// System.out.println("dexbuffer:"+Arrays.toString(dexbuffer));
		return bb;
	}

	public int getInt(int offset) {
		return Utils.intFrombytes(dexbuffer, offset);
	}

	public int getShort(int offset) {
		return Utils.shortFrombytes(dexbuffer, offset);
	}

	static final String CLASSESDEX = "classes.dex";

	private byte[] getBytesFromClassesDex(int offset, int length,
			boolean copystep) throws IOException {
		String file = theFileName;
		if (dexbuffer.length == 0) {
			jlog.info("*"+file+"*");
			try {
				JarFile f = new JarFile(file);

				JarEntry je = f.getJarEntry(CLASSESDEX);
				if (je == null) {
					throw new FileNotFoundException(CLASSESDEX + " in " + file
							+ " not found");
				}
				long l_plen = (int) je.getSize();
				int plen = (int) l_plen;
				if (l_plen > Integer.MAX_VALUE) {
					Utils.stopAndDump("ende");
				}
				InputStream fis = f.getInputStream(je);
				byte b[] = new byte[plen];
				int pos = 0;
				int k = 0;
				// System.out.println("p=" + plen);
				while (k != -1) {
					// System.out.println("k=" + k+"/"+plen);
					int all = fis.available();
					// System.out.println("all=" + all);
					k = fis.read(b, pos, all);
					pos = pos + k;
					if (k == 0) {
						break;
					}
				}
				dexbuffer = b;
			} catch (ZipException e) {
				e.printStackTrace();
				throw new ZipException(file + " not found:" + e);
			}
			// System.out.println(Arrays.toString(b));
			// System.out.println(b.length);
			// System.out.println("k=" + k);
			// Utils.stopAndDump("array read");
		}
		byte bb[] = null;
		if (copystep) {
			if (offset == 0 && length == -1) {
				return dexbuffer.clone();
			}
			bb = new byte[length];
			System.arraycopy(dexbuffer, offset, bb, 0, length);
		} else {
			bb = new byte[0];
		}

		return bb;
	}

}