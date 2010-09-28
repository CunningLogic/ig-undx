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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.illegalaccess.undx.APKAccess;
import org.illegalaccess.undx.Utils;
import org.illegalaccess.undx.tools.FileList;

public class ClassCollection extends Hashtable<String, DexClassDetails> {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static Pattern xx = Pattern.compile("(\\d+?)", Pattern.CASE_INSENSITIVE);
	static Pattern yy = Pattern.compile("Class descriptor  : '(.+?)'",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
	static Pattern zz = Pattern.compile("Superclass        : '(.+?)'",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

	static String vmsplit = "  Virtual methods   -";
	static String ifsplit = "  Instance fields   -";

	OdexFileDetails odexfile;

	private static Logger jlog = Logger
			.getLogger("org.illegalaccess.undx.ClassCollection");

	public int add(OdexFileDetails ofd, String[] classes) {
		int anzahl = 0;
		jlog.fine("classes found:" + classes.length);

		for (String theclass : classes) {
			jlog.fine("class:"
					+ (theclass.length() == 0 ? "empty classname" : theclass
							.substring(0, Math.min(200, theclass.length()))));
			String[] split = theclass.split(vmsplit);
			if (split.length == 1) {
				continue;
			}
			String meths = theclass.split(vmsplit)[1];
			MethodCollection details = new MethodCollection(meths);

			String fields = theclass.split(ifsplit)[1];
			fields = fields.split(" Direct methods    -")[0];
			FieldCollection fielddetails = new FieldCollection(fields);

			// for (int i = 0 ; i < fielddetails.size(); i++ ){
			// jlog.info(fielddetails.get(i).toString());
			// }
			int num = 0;
			Matcher p = xx.matcher(theclass);
			p.find();
			num = Integer.parseInt(p.group(0));
			jlog.fine("num=" + num);
			Matcher q = yy.matcher(theclass);
			q.find();
			String classdesc = q.group(1);
			jlog.fine("classdesc=" + classdesc);
			Matcher r = zz.matcher(theclass);
			r.find();
			String superclass = "";
			MethodCollection vtable = null;
			if (!classdesc.equals("Ljava/lang/Object;")) {
				superclass = r.group(1);

			} else {
				vtable = details;
			}
			jlog.fine("superclass=" + superclass);

			DexClassDetails dcd = new DexClassDetails(num, superclass,
					classdesc, details, vtable, fielddetails, ofd);
			put(classdesc, dcd);
			anzahl++;
		}

		if (anzahl == 0) {
			jlog.severe(Arrays.toString(classes));
		}

		return anzahl;
	}

	public DexMethodDetails getVTableEntryForClass(String theClass, int i) {
		DexClassDetails item = get(theClass);
		jlog.fine(item.toString());
		jlog.fine(item.vtable.toString());
		return item.vtable.get(i);
	}

	void mergevtable_nocopy(String cname, String cnamep) {
		DexClassDetails item = get(cnamep);
		if (item.vtable == null) {
			mergevtable_nocopy(cnamep, item.superclass);
			item = get(cnamep);
		}
		DexClassDetails itemp = get(cname);

		MethodCollection vtableneu = new MethodCollection();

		int i = 0;

		for (int ii = 0; ii < item.vtable.size(); ii++) {
			// Integer key =item.vtable.next();
			vtableneu.add(ii, item.vtable.get(ii));
			i++;
		}

		for (int ii = 0; ii < itemp.meths.size(); ii++) {

			DexMethodDetails mi = itemp.meths.get(ii);
			boolean found = false;
			Integer idx = -1;
			for (int jj = 0; jj < item.vtable.size(); jj++) {
				DexMethodDetails mi2 = item.vtable.get(jj);
				if (mi.name.equals(mi2.name) && (mi.sig.equals(mi2.sig))) {
					found = true;
					idx = jj;
					break;
				}
			}

			if (found) {
				vtableneu.set(idx, mi);
			} else {
				// System.out.println(i);
				vtableneu.ensureCapacity(i * 2);
				vtableneu.add(i, mi);
				i++;

			}
		}
		DexClassDetails newItem = new DexClassDetails(itemp);
		newItem.vtable = vtableneu;
		put(cname, newItem);
	}

	// def parseMethod(m):
	// proto="""
	// #0 : (in Landroid/util/EventLogFunctionalTest;)
	// name : 'disableTestReadCompoundEntry'
	// type : '()V'
	// access : 0x0001 (PUBLIC)
	// code -
	// registers : 19
	// ins : 1
	// outs : 3
	// insns size : 264 16-bit code units"""
	//
	// searchit =
	// "#(\d+)\s+\:\s\(in\s(.+?)\).+?'(.+?)'.+?'(.+?)'.+?access\s+?\:\s(.+?)\s\((.*?)\)"
	// # searchit = "\#\d+\s+\:\s\(.+?\)"
	// z = re.compile(searchit,re.I|re.S|re.M)
	// k= z.findall(m)
	//	
	// return k

	ClassCollection(String startdir) throws IOException {

		List<File> f = FileList.getFileListingWithExt(new File(startdir),
				"core.odex");
		initFromFileList(f);

	}

	public ClassCollection(List<File> fi) throws IOException {
		initFromFileList(fi);
	}

	private void initFromFileList(List<File> f) throws FileNotFoundException,
			IOException {
		FileCollection odex = new FileCollection();
		for (File fi : f) {
			List<String> deps = new ArrayList<String>();
			String filename = fi.getAbsolutePath();
			FileInputStream fis = new FileInputStream(fi);
			int x = fis.available();
			byte b[] = new byte[x];
			int k = fis.read(b);
			if (k != x) {
				Utils.stopAndDump("short read");
			}
			for (int i = 0; i < b.length - 4; i++) {
				if (b[i] == '.' && b[i + 1] == 'o' && b[i + 2] == 'd'
						&& b[i + 3] == 'e' && b[i + 4] == 'x') {
					int j = i - 1;
					String str = ".odex";
					boolean theend = false;
					while (j > 0 && !theend) {
						Character thechar = new Character((char) b[j]);
						if (Character.isJavaIdentifierPart(thechar)) {
							str = thechar + str;
							j--;
						} else
							theend = true;
					}
					deps.add(str);
					jlog.fine("dep added:" + str);
				}
			}
			APKAccess apk = APKAccess.fromFile(fi);
			String z = apk.getDumpFromAPK();
			// jlog.fine("dump:" + z.length());
			// jlog.info("dump:" + z.substring(1,Math.min(100,z.length())));
			// if (fi.getName().endsWith("core.odex")) {
			// jlog.info(z);
			// }
			String classes[] = z.split("Class\\ \\#");

			OdexFileDetails ofd = new OdexFileDetails(filename, deps, z,
					classes, this);
			int anzahl = add(ofd, classes);
			if (odex.get(filename) != null) {
				Utils.stopAndDump(filename + ":already loaded");
			}

			jlog.info("loaded:" + filename + "/" + anzahl + "/" + size());

			for (String str : keySet()) {
				jlog.fine(str);
			}

			odex.put(filename, ofd);
		}

		for (DexClassDetails cclass : this.values()) {
			if (cclass.classdesc.equals("Ljava/lang/Object;")
					|| cclass.classdesc.length() == 0) {
				jlog.fine("funny class:" + cclass.classdesc);
				continue;
			}
			DexClassDetails parent = get(cclass.superclass);
			assert (parent != null);
			jlog.fine(cclass.classdesc);
			jlog.fine(cclass.superclass);
			jlog.fine(parent.classdesc);

			mergevtable_nocopy(cclass.classdesc, parent.classdesc);

		}
	}

}
