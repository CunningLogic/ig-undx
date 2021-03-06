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

//TODO: Peephole optimize: http://cibyl.googlecode.com/svn/trunk/tools/python/Cibyl/PeepholeOptimizer/parse.py
//Defered checkcast, checkcast merken, vor verwendung des registers bei n�chster instruktion reinmogeln	

// TODO: funny name <undx>

// TODO: Constant Double 0.0
import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.prefs.*;

import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import java.util.jar.JarOutputStream;
import java.util.logging.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.generic.*;
import org.apache.bcel.verifier.Verifier;
import org.apache.bcel.verifier.VerifierFactory;
import org.illegalaccess.undx.types.ClassCollection;

import org.apache.bcel.Repository;
import org.apache.bcel.classfile.ClassParser;

// IEEE 754 Conversion here, http://www.h-schmidt.net/FloatApplet/IEEE754de.html

class VerificationResult {
	public static void doit(String archive, String file) {
		Verifier[] vf = VerifierFactory.getVerifiers();
		for (int i = 0; i < vf.length; i++) {
			System.out.println(vf[i]);
		}
	}
}

class DeferredTableSwitch extends TABLESWITCH {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String _addrdata;
	String _origoffset;

	public DeferredTableSwitch(String origoffset, String data) {
		super(new int[0], new InstructionHandle[0], null);
		_addrdata = data;
		_origoffset = origoffset;
	}

	public String getAddr() {
		return _addrdata;
	}

	public String getOrigOffset() {
		return _origoffset;
	}
}

public class DalvikToJVM {

	String outpref = "";

	private static Logger jlog = Logger.getLogger(DalvikToJVM.class.getName());
	
	public static String askloc = "";

	public static ClassCollection cc;
	
	public static String user = System.getProperty( "user.name" );
	public static String os = System.getProperty( "os.name" );
	public static String sep = System.getProperty( "file.separator" );

	private static Preferences prefs;

	APKAccess _apa;

	static {
		jlog.setLevel(Level.ALL);
	}

	public static void main(String[] argv) throws Exception {
		/* TODO: Im Groovy Script entfernen */

		boolean debug = false;
		boolean verify = false;
		boolean dohelp = true; // without options show help

		String filename = "";
		String otafile = "";
		String outputdir = "gen";
		
		prefs = Preferences.userNodeForPackage(DalvikToJVM.class);

		LongOpt[] longopts = new LongOpt[8];

		longopts[0] = new LongOpt("ASDKLoc", LongOpt.OPTIONAL_ARGUMENT, null, 's');
		longopts[1] = new LongOpt("debug", LongOpt.NO_ARGUMENT, null, 'd');
		longopts[2] = new LongOpt("outputdir", LongOpt.REQUIRED_ARGUMENT, null, 'O');
		longopts[3] = new LongOpt("filename", LongOpt.REQUIRED_ARGUMENT, null, 'f');
		longopts[4] = new LongOpt("updatefiles", LongOpt.OPTIONAL_ARGUMENT,	null, 'u');
		longopts[5] = new LongOpt("verify", LongOpt.OPTIONAL_ARGUMENT, null, 'v');
		longopts[6] = new LongOpt("help", LongOpt.NO_ARGUMENT, null, 'h');
		longopts[7] = new LongOpt("clear", LongOpt.NO_ARGUMENT, null, 'c');

		String arg;
		Getopt go = new Getopt("undx", argv, ":s:dvo:f:hc", longopts);
		int c = 0;
		while ((c = go.getopt()) != -1) {
			switch (c) {
			case 's':
				arg = go.getOptarg().trim();
				jlog.info("You picked option '" + (char) c + "' with argument "
						+ ((arg != null) ? arg : "null"));
				askloc = arg;
				break;
			case 'd':
				debug = true;
				jlog.info("Debug activated':" + (char) c);
				break;

			case 'v':
				verify = true;
				jlog.info("Verify activated':" + (char) c);
				break;
			case 'O':
				outputdir = go.getOptarg().trim();
				jlog.info("Odir activated':" + outputdir);
				break;

			case 'f':
				filename = go.getOptarg().trim();
				jlog.info("Filename':*" + filename + "*");
				dohelp=false;
				break;
			case 'h':
				dohelp = true;
				break;
			case 'u':
				otafile = go.getOptarg().trim();
				jlog.info("OTAFile':" + otafile);
				break;
			case 'c':
				prefs.clear();
				System.out.println("Preferences cleared");
				dohelp=true;
				break;
			}

		}

		if (dohelp) {
			showHelp(); 
			System.exit(0);
		}
		
		if( askloc.equals("") ) {
			findASDK();
		}
		
		System.out.println("Using ASDKLoc: " + askloc);

		List<File> lf = new ArrayList<File>();

		String outpref = System.getProperty("undx.destdir", outputdir);

		cc = new ClassCollection(lf);

		DalvikToJVM dtj = new DalvikToJVM(outpref);
		try {
			dtj.doConvert(debug, verify, filename, otafile);
		} catch (Exception e) {
			System.out.println("usage: DalvikToJVM dexfile");

			if (!(e instanceof ZipException)
					&& !(e instanceof FileNotFoundException)) {
				System.out.println("Make sure to set the specific the Android SDK location with -s"
								+ " i.e., -s /home/user/android-adb/android-sdk-linux_86/platforms/android-8\n"
								+ "Current ASKLoc: " + askloc);
				System.out.println("caught exception:");
				e.printStackTrace(System.out);
			} else {
				System.out.println(e);
			}
		}
	}

	private static void showHelp() {
		System.out.println("DalvikToJVM"); 
		System.out.println("-f 			<apkfile> " ); 
		System.out.println("-d          enable debug"); 
		System.out.println("-h          show help"); 
		System.out.println("-v          enable verification"); 
		System.out.println("-s          Android SDK Location"); 
		System.out.println("-o          output directory");
		System.out.println("-c          clear previous search location");
	}

	private static boolean isOTA(String z) throws IOException {
		ZipFile zf = new ZipFile(z);
		Enumeration<ZipEntry> e = (Enumeration<ZipEntry>) zf.entries();
		boolean hasodex = false;

		for (; e.hasMoreElements();) {
			ZipEntry ze = e.nextElement();
			if (ze.getName().endsWith(".odex")) {
				hasodex = true;
			}
		}
		return hasodex;

	}
	
	public static void findASDK() {
		//we haven't already done and stored the search.
		if( prefs.get("askloc","").equals("") ) {
			String userhome = System.getProperty("user.home");
			System.out.println("Searching for ASDKLoc in " + userhome + "...");
			
			myFindASDK( new File( userhome ) );
			
			//not blank, we found it!
			if( !askloc.equals("") ) {
				try {
					prefs.put("askloc", askloc);
				} catch( NullPointerException e ) {
					System.out.println("Cannot set preference: " + e.getMessage() );
				}
			} else {
				System.out.println("Could not find ASDK");
			}
		//the search was already done, load it up.
		} else {
			askloc = prefs.get("askloc","");
		}
	}
	
	private static void myFindASDK(File root) {
		if( askloc.equals( "" ) ) {
			String[] children = root.list();
			if( children != null ) {
				for (int i=0; i < children.length; i++) {
					File f = new File(root, children[i]);
					//System.out.println("f: " + f.toString() );
					if( f.exists() && f.canRead() && f.isDirectory() ) {
						if( f.toString().contains("android-sdk-") ) {
							//System.out.println("FILE: " + f.toString() );
							askloc = new File( f.getAbsolutePath() + sep + "platforms" + sep +
									"android-" + findVersion( f ) ).toString();
							break;
						} else {
							myFindASDK( f );
						}
					}
				}
			}
		}
	}

	public static String findVersion(File f) {
		Integer version = 0;
		File path = new File( f.getAbsolutePath() + sep + "platforms" );
		String[] children = path.list();
		for (int i=0; i < children.length; i++ ) {
			int t = Character.digit(children[i].charAt( children[i].length()-1 ),10);
			//System.out.println("version = " + t);
			if( t > version ) {
				version = t;
			}
		}
		//System.out.println(version.toString());
		return version.toString();
	}
	
	public DalvikToJVM(String _outpref) {
		outpref = _outpref;

	}

	APKAccess getAPA() {
		return _apa;
	}

	void setAPA(APKAccess apa) {
		_apa = apa;
	}

	static private String escapeSpaces(String z) {
		return z.replaceAll("\\ ", "\\\\ ");
	}

	private void doConvert(boolean debug, boolean doVerify, String filename,
			String otafile) throws IOException {

		// String otafile = "";
		boolean otamode = false;
		// int idx = 0;
		String z = "";
		// jlog.severe(Arrays.toString(arr));

		if (otafile.length() > 0) {
			// if (arr.length > 1) {
			otamode = isOTA(otafile);
			// z = arr[1];

			ZipInputStream zis = new ZipInputStream(
					new FileInputStream(otafile));
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				System.out.println("Unzipping: " + entry.getName());
				if (entry.getName().equals(z)) {
					int size;
					byte[] buffer = new byte[2048];
					File f = new File(entry.getName());
					z = "xxx" + f.getName();
					FileOutputStream fos = new FileOutputStream(z);
					BufferedOutputStream bos = new BufferedOutputStream(fos,
							buffer.length);

					while ((size = zis.read(buffer, 0, buffer.length)) != -1) {
						bos.write(buffer, 0, size);
					}
					bos.flush();
					bos.close();
				}
			}

		} else {
			z = filename;

		}
		System.out.println("OTA Mode: " + otamode);

		// String z = arr[idx];
		String dest = new File(z).getName() + ".jar";

		String destdump = new File(z).getName() + ".dump";
		String destdex = new File(z).getName() + ".dex";

		APKAccess apa = new APKAccess(z);
		this.setAPA(apa);
		String contents = "";
		if (z.endsWith(".apk") || z.endsWith(".odex") || z.endsWith(".dex")) {
			contents = apa.getDumpFromAPK();
			try {
				new File(outpref).mkdir();
			} catch (Exception e) {
				//
			}
			FileOutputStream fos = new FileOutputStream(outpref + "/"
					+ destdump);
			fos.write(contents.getBytes());
			fos.close();
		} else {
			FileInputStream fis = new FileInputStream(z);
			// InputStreamReader isr = new InputStreamReader(fis);
			int zz = fis.available();
			byte[] b = new byte[zz];
			int k = fis.read(b);
			if (k != b.length) {
				jlog.info(Arrays.toString(b));
				Utils.stopAndDump("content too short");
			}
			contents = new String(b);
			fis.close();
		}
		byte[] bytes = apa.dexbuffer;
		Utils.writeBytebufferToFile(outpref + "/" + destdex, bytes);

		String[] classes = contents.split("Class \\#");
		jlog.info("Classes count=" + classes.length);
		try {
			new File(outpref).mkdir();
		} catch (Exception e) {
			//
		}
		JarOutputStream out = new JarOutputStream(new FileOutputStream(outpref
				+ "/" + dest));

		// {

		/**
		 * @see java.util.zip.ZipOutputStream#close()
		 */
		// public void close() throws IOException {
		// this.closeEntry();
		// }
		// };
		for (String theklass : classes) {
			try {
				System.out.println(theklass.contains("Class descriptor"));
				if (theklass.contains("Class descriptor")) {
					ClassHandler ch = new ClassHandler(outpref, theklass, out,
							getAPA());
					jlog.info("started" + ch.getClassName());
					ch.doit();

					jlog.info("finished" + ch.getClassName());
					// break;
					// System.exit(0);
				}
			} catch (Exception e) {
				jlog.severe("error converting " + theklass);
			}
			// out.flush();
		}
		out.close();
		if (doVerify) {
			doVerification(dest);
		}
	}

	public void doVerification(String dest) throws FileNotFoundException,
			IOException {
		String verifile = outpref + "/" + dest;
		File f = new File(verifile);
		jlog.info("Verify:" + verifile);
		FileInputStream fis = new FileInputStream(f);
		JarInputStream jis = new JarInputStream(fis);
		// boolean end = false;
		JarEntry je = null;
		URLClassLoader ucl = getTestClassLoader(f);

		// NativeVerifier vf = (NativeVerifier) VerifierFactory
		// .getVerifier("org.apache.bcel.verifier.NativeVerifier");
		while ((je = jis.getNextJarEntry()) != null) {
			// long toread = je.getSize();
			String thename = je.getName();
			byte[] b = new byte[2];
			String thefilename = "";
			try {
				// URLClassLoader ucl = getTestClassLoader(f);
				// System.out.println(url1);
				// System.out.println(url2);

				long k = je.getSize();

				if (k > Integer.MAX_VALUE) {
					Utils.stopAndDump("too bigg");
				}

				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				int pos = 0;
				// System.out.println(k);
				while (jis.read(b, 0, 1) > 0) {
					bos.write(b, 0, 1);
					pos++;
				}

				thefilename = thename;

				File thefile = new File(thefilename).getAbsoluteFile();
				// System.out.println(thefile+":"+pos);

				// int read = jis.read(b,0,realsize);

				String parent = thefile.getParent();

				String msg = "try to create " + parent + " parent:";
				try {
					File path = new File(parent);
					path.mkdirs();
					jlog.info(msg + "succeeded");
				} catch (Exception e) {
					jlog.info(msg + "failed");
					e.printStackTrace();
				}

				FileOutputStream fos = new FileOutputStream(thefile);
				fos.write(bos.toByteArray());
				fos.close();

				String thenewname = thename.replaceAll(".class", "");
				thenewname = thenewname.replaceAll("/", ".");

				System.out.println("Testing:" + thenewname);
				try {
					Class x = Class.forName(thenewname, true, ucl);
				} catch (Exception e) {
					e.printStackTrace();
				}

				try {
					ClassParser p = new ClassParser(thefilename);
					JavaClass jc = p.parse();
					Repository.addClass(jc);
					PrintStream oldout = System.out;
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					System.setOut(new PrintStream(
							new BufferedOutputStream(baos), true));
					Verifier.main(new String[] { thenewname });
					System.setOut(oldout);
					baos.flush();
					jlog.info(baos.toString());
				} catch (Exception e) {
					e.printStackTrace();
				}

			} catch (Throwable e) {
				e.printStackTrace();
				// System.out.println(thenewname + ":" + e);
			}

		}
	}

	private static URLClassLoader getTestClassLoader(File f)
			throws MalformedURLException {
		URL url1 = new URL("file://" + f.getAbsolutePath());
		URL url3 = new URL("file://tmp/");
		URL url4 = new URL("file://" + new File(".").getAbsolutePath());
		URL url5 = new URL("file://" + askloc + "/android.jar");

		URLClassLoader ucl = new URLClassLoader(new URL[] { url4, url1, url3,
				url5 });
		return ucl;
	}
}
