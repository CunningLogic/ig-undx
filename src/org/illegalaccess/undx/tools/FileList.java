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

package org.illegalaccess.undx.tools;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


public class FileList {
	

	static private List<File> getFileListing(File aStartingDir)
			throws FileNotFoundException {
		valDir(aStartingDir);
		List<File> result = getFileListingNoSort(aStartingDir);
		Collections.sort(result);
		return result;
	}

	public static List<File> getFileListingWithExt(File astartingDir, String ext) throws FileNotFoundException{
		List<File> f = getFileListing(astartingDir);
		List<File> result = new ArrayList<File>();
		for (File fi : f) {
			if (fi.getName().endsWith(ext)) {
				result.add(fi);
			}
		}
		return result;
	}

	static private List<File> getFileListingNoSort(File aStartingDir)
			throws FileNotFoundException {
		List<File> result = new ArrayList<File>();
		File[] filesAndDirs = aStartingDir.listFiles();
		List<File> filesDirs = Arrays.asList(filesAndDirs);
		for (File file : filesDirs) {
			result.add(file); 
			if (!file.isFile()) {
				List<File> deeperList = getFileListingNoSort(file);
				result.addAll(deeperList);
			}
		}
		return result;
	}

	static private void valDir(File aDirectory)
			throws FileNotFoundException {
		if (aDirectory == null) {
			throw new IllegalArgumentException("Dir should not be null.");
		}
		if (!aDirectory.exists()) {
			throw new FileNotFoundException("Dir not exists: "
					+ aDirectory);
		}
		if (!aDirectory.isDirectory()) {
			throw new IllegalArgumentException("not a dir: "
					+ aDirectory);
		}
		if (!aDirectory.canRead()) {
			throw new IllegalArgumentException("Dir not readable: "
					+ aDirectory);
		}
	}
}

